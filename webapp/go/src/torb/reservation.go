package main

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	FullReserved = errors.New("full")
	NotReserved  = errors.New("not reserved")
	NotOwner     = errors.New("not a valid owner")

	mReservation       sync.RWMutex
	eventReservations  map[int64][]Reservation
	eventReservedFlags map[int64][]int64

	mDiffLog     sync.Mutex
	logReserved  []Reservation
	logCancelled []CancelLog

	mReport     sync.Mutex
	reportData  []ReportCache
	reportIndex map[int64]int
)

type ReportCache struct {
	ID       int64
	SoldAt   time.Time
	Rendered string
}
type CancelLog struct {
	ID int64
	At time.Time
}

const reportTimeFormat = "2006-01-02T15:04:05.000000Z"

func formatReport(r Reservation, price int64) string {
	s := sheetInfo(r.SheetID)
	price += s.Price
	soldAt := r.ReservedAt.Format(reportTimeFormat)
	canceledAt := ""
	if r.CanceledAt != nil {
		canceledAt = r.CanceledAt.Format(reportTimeFormat)
	}
	return fmt.Sprintf("%d,%d,%s,%d,%d,%d,%s,%s\n",
		r.ID, r.EventID, s.Rank, s.Num, price, r.UserID, soldAt, canceledAt)
}

func initEventPrice() map[int64]int64 {
	query := "SELECT id, price FROM events"
	rows, err := db.Query(query)
	for err != nil {
		log.Println(err)
		rows, err = db.Query(query)
	}
	defer rows.Close()

	ps := make(map[int64]int64)
	for rows.Next() {
		var id, price int64
		err := rows.Scan(&id, &price)
		if err != nil {
			panic(err)
		}
		ps[id] = price
	}

	return ps
}

func initReservation() {
	mReservation.Lock()
	defer mReservation.Unlock()
	mDiffLog.Lock()
	defer mDiffLog.Unlock()

	eventReservations = make(map[int64][]Reservation)
	eventReservedFlags = make(map[int64][]int64)
	priceMap := initEventPrice()

	query := "SELECT * FROM reservations"
	rows, err := db.Query(query)
	for err != nil {
		log.Println(err)
		rows, err = db.Query(query)
	}
	defer rows.Close()

	for rows.Next() {
		var r Reservation
		err := rows.Scan(&r.ID, &r.EventID, &r.SheetID, &r.UserID, &r.ReservedAt, &r.CanceledAt)
		if err != nil {
			panic(err)
		}
		if r.CanceledAt == nil {
			eventReservations[r.EventID] = append(eventReservations[r.EventID], r)
		}
		reportData = append(reportData, ReportCache{ID: r.ID, SoldAt: *r.ReservedAt, Rendered: formatReport(r, priceMap[r.EventID])})
	}

	reportIndex = make(map[int64]int)
	sort.Slice(reportData, func(i, j int) bool { return reportData[i].SoldAt.Before(reportData[j].SoldAt) })
	for i, r := range reportData {
		reportIndex[r.ID] = i
	}

	for eid := range eventReservations {
		eventReservedFlags[eid] = make([]int64, 1001)
		rr := eventReservations[eid]
		for _, r := range rr {
			eventReservedFlags[eid][r.SheetID] = r.UserID
		}
	}
}

func getReservationForEvent(eventID int64) ([]Reservation, []int64) {
	mReservation.RLock()
	defer mReservation.RUnlock()
	return eventReservations[eventID], eventReservedFlags[eventID]
}

func doReserve(eventID, userID int64, rank string) (int64, int64, error) {
	mReservation.Lock()
	defer mReservation.Unlock()

	m, ok := eventReservedFlags[eventID]
	if !ok {
		m = make([]int64, 1001)
		eventReservedFlags[eventID] = m
	}

	var start, end int64
	switch rank {
	case "S":
		start = 1
		end = 50
		break
	case "A":
		start = 51
		end = 200
	case "B":
		start = 201
		end = 500
	default:
		start = 501
		end = 1000
	}

	var sheetID int64

	x := rand.Int63n(end-start+1) + start
	for i := x; i <= end; i++ {
		if m[i] == 0 {
			sheetID = i
			break
		}
	}
	if sheetID == 0 {
		var i int64
		for i = start; i < x; i++ {
			if m[i] == 0 {
				sheetID = i
				break
			}
		}
	}
	if sheetID == 0 {
		return 0, 0, FullReserved
	}

	now := time.Now().UTC()
	res, err := db.Exec("INSERT INTO reservations (event_id, sheet_id, user_id, reserved_at) VALUES (?, ?, ?, ?)",
		eventID, sheetID, userID, now.Format("2006-01-02 15:04:05.000000"))

	if err != nil {
		log.Printf("failed to insert reservation: %v", err)
		return 0, 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		log.Printf("failed to insert reservation: %v", err)
		return 0, 0, err
	}

	num := sheetID - start + 1
	//log.Printf("reserved event=%v, sheetID=%v, sheetNum=%v, userID=%v",
	//	eventID, sheetID, num, userID)
	newResv := Reservation{ID: id, EventID: eventID, SheetID: sheetID, UserID: userID, ReservedAt: &now}
	eventReservedFlags[eventID][sheetID] = userID
	eventReservations[eventID] = append(eventReservations[eventID], newResv)

	mDiffLog.Lock()
	logReserved = append(logReserved, newResv)
	mDiffLog.Unlock()
	return id, num, nil
}

func cancelReservation(eventID, sheetNum, userID int64, rank string) error {
	var sheetID int64
	switch rank {
	case "S":
		sheetID = sheetNum
	case "A":
		sheetID = sheetNum + 50
	case "B":
		sheetID = sheetNum + 200
	case "C":
		sheetID = sheetNum + 500
	}
	//log.Printf("cancelling event=%v, sheetID=%v, rank=%v, sheetNum=%v, userID=%v",
	//	eventID, sheetID, rank, sheetNum, userID)

	mReservation.Lock()
	defer mReservation.Unlock()

	m, ok := eventReservedFlags[eventID]
	if !ok || m[sheetID] == 0 {
		log.Println("not reserved")
		return NotReserved
	}
	if m[sheetID] != userID {
		log.Printf("not owner: owner=%v", m[sheetID])
		return NotOwner
	}

	var ri int
	var rID int64
	var r Reservation
	rrr := eventReservations[eventID]
	for ri, r = range rrr {
		if r.SheetID == sheetID {
			rID = r.ID
			break
		}
	}

	if rID == 0 {
		return errors.New("XXX: BAD SheetNum")
	}

	now := time.Now().UTC()
	if _, err := db.Exec("UPDATE reservations SET canceled_at = ? WHERE id = ?", now.Format("2006-01-02 15:04:05.000000"), rID); err != nil {
		return err
	}

	rrr[ri] = rrr[len(rrr)-1]
	rrr = rrr[:len(rrr)-1]
	eventReservations[eventID] = rrr
	//	eventReservations[eventID] = append(
	//		eventReservations[eventID][:ri],
	//		eventReservations[eventID][ri+1:]...)
	eventReservedFlags[eventID][sheetID] = 0

	mDiffLog.Lock()
	logCancelled = append(logCancelled, CancelLog{ID: rID, At: now})
	mDiffLog.Unlock()

	//log.Printf("canceled event=%v, sheetID=%v, sheetNum=%v, userID=%v",
	//	eventID, sheetID, sheetNum, userID)
	return nil
}

func UpdateReport() {
	priceMap := initEventPrice()

	mDiffLog.Lock()
	newResv := logReserved
	logReserved = nil
	newCancels := logCancelled
	logCancelled = nil
	mDiffLog.Unlock()

	mReport.Lock()
	defer mReport.Unlock()

	for _, r := range newResv {
		s := formatReport(r, priceMap[r.EventID])
		reportIndex[r.ID] = len(reportData)
		reportData = append(reportData, ReportCache{ID: r.ID, Rendered: s})
	}

	for _, c := range newCancels {
		ix := reportIndex[c.ID]
		rs := reportData[ix].Rendered
		var b strings.Builder
		b.WriteString(rs[:len(rs)-1]) // trim \n
		b.WriteString(c.At.Format(reportTimeFormat))
		b.WriteRune('\n')
		reportData[ix].Rendered = b.String()
	}
}
