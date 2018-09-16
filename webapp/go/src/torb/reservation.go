package main

import (
	"errors"
	"log"
	"math/rand"
	//"sort"
	"sync"
	"time"
)

var (
	FullReserved = errors.New("full")
	NotReserved  = errors.New("not reserved")
	NotOwner     = errors.New("not a valid owner")

	mReservation       sync.Mutex
	eventReservations  map[int64][]Reservation
	eventReservedFlags map[int64][]int64
)

func initReservation() {
	mReservation.Lock()
	defer mReservation.Unlock()
	eventReservations = make(map[int64][]Reservation)
	eventReservedFlags = make(map[int64][]int64)

	rows, err := db.Query("SELECT * FROM reservations WHERE canceled_at IS NULL")
	if err != nil {
		panic(err)
	}

	for rows.Next() {
		var r Reservation
		err := rows.Scan(&r.ID, &r.EventID, &r.SheetID, &r.UserID, &r.ReservedAt, &r.CanceledAt)
		if err != nil {
			panic(err)
		}
		eventReservations[r.EventID] = append(eventReservations[r.EventID], r)
	}

	for eid := range eventReservations {
		eventReservedFlags[eid] = make([]int64, 1001)

		rr := eventReservations[eid]
		//sort.Slice(rr, func(i, j int) bool {
		//	return rr[i].SheetID < rr[j].SheetID
		//})
		//eventReservations[eid] = rr

		for _, r := range rr {
			eventReservedFlags[eid][r.SheetID] = r.UserID
		}
	}
}

func getReservationForEvent(eventID int64) ([]Reservation, []int64) {
	mReservation.Lock()
	defer mReservation.Unlock()
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

	//TODO: random
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
	log.Printf("reserved event=%v, sheetID=%v, sheetNum=%v, userID=%v",
		eventID, sheetID, num, userID)
	eventReservedFlags[eventID][sheetID] = userID
	eventReservations[eventID] = append(
		eventReservations[eventID], Reservation{ID: id, EventID: eventID, SheetID: sheetID, UserID: userID, ReservedAt: &now})
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
	log.Printf("cancelling event=%v, sheetID=%v, rank=%v, sheetNum=%v, userID=%v",
		eventID, sheetID, rank, sheetNum, userID)

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
	for ri, r = range eventReservations[eventID] {
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

	eventReservations[eventID] = append(
		eventReservations[eventID][:ri],
		eventReservations[eventID][ri+1:]...)
	eventReservedFlags[eventID][sheetID] = 0

	log.Printf("canceled event=%v, sheetID=%v, sheetNum=%v, userID=%v",
		eventID, sheetID, sheetNum, userID)
	return nil
}
