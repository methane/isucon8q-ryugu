package main

import (
	"bytes"
	//"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
	"github.com/methane/zerotimecache"
	"golang.org/x/sync/singleflight"
)

var (
	users     map[int64]*User  = make(map[int64]*User)
	usersName map[string]*User = make(map[string]*User)
	userLock  sync.Mutex
)

var (
	eventLock sync.Mutex
	eventOk   map[int64]bool
)

type User struct {
	ID        int64  `json:"id,omitempty"`
	Nickname  string `json:"nickname,omitempty"`
	LoginName string `json:"login_name,omitempty"`
	PassHash  string `json:"pass_hash,omitempty"`
}

type Event struct {
	ID       int64  `json:"id,omitempty"`
	Title    string `json:"title,omitempty"`
	PublicFg bool   `json:"public,omitempty"`
	ClosedFg bool   `json:"closed,omitempty"`
	Price    int64  `json:"price,omitempty"`

	Total   int                `json:"total"`
	Remains int                `json:"remains"`
	Sheets  map[string]*Sheets `json:"sheets,omitempty"`
}

type Sheets struct {
	Total   int     `json:"total"`
	Remains int     `json:"remains"`
	Detail  []Sheet `json:"detail,omitempty"`
	Price   int64   `json:"price"`
}

type Sheet struct {
	ID    int64  `json:"-"`
	Rank  string `json:"-"`
	Num   int64  `json:"num"`
	Price int64  `json:"-"`

	Mine           bool       `json:"mine,omitempty"`
	Reserved       bool       `json:"reserved,omitempty"`
	ReservedAt     *time.Time `json:"-"`
	ReservedAtUnix int64      `json:"reserved_at,omitempty"`
}

type Reservation struct {
	ID         int64      `json:"id"`
	EventID    int64      `json:"-"`
	SheetID    int64      `json:"-"`
	UserID     int64      `json:"-"`
	ReservedAt *time.Time `json:"-"`
	CanceledAt *time.Time `json:"-"`

	Event          *Event `json:"event,omitempty"`
	SheetRank      string `json:"sheet_rank,omitempty"`
	SheetNum       int64  `json:"sheet_num,omitempty"`
	Price          int64  `json:"price,omitempty"`
	ReservedAtUnix int64  `json:"reserved_at,omitempty"`
	CanceledAtUnix int64  `json:"canceled_at,omitempty"`
}

type Administrator struct {
	ID        int64  `json:"id,omitempty"`
	Nickname  string `json:"nickname,omitempty"`
	LoginName string `json:"login_name,omitempty"`
	PassHash  string `json:"pass_hash,omitempty"`
}

var thCh = make(chan struct{}, 1)

// USAGE: defer throttle()()
func throttle() func() {
	thCh <- struct{}{}
	return func() {
		<-thCh
	}
}

func sessUserID(c echo.Context) int64 {
	sess, _ := session.Get("session", c)
	var userID int64
	if x, ok := sess.Values["user_id"]; ok {
		userID, _ = x.(int64)
	}
	return userID
}

func sessSetUserID(c echo.Context, id int64) {
	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
	}
	sess.Values["user_id"] = id
	sess.Save(c.Request(), c.Response())
}

func sessDeleteUserID(c echo.Context) {
	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
	}
	delete(sess.Values, "user_id")
	sess.Save(c.Request(), c.Response())
}

func sessAdministratorID(c echo.Context) int64 {
	sess, _ := session.Get("session", c)
	var administratorID int64
	if x, ok := sess.Values["administrator_id"]; ok {
		administratorID, _ = x.(int64)
	}
	return administratorID
}

func sessSetAdministratorID(c echo.Context, id int64) {
	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
	}
	sess.Values["administrator_id"] = id
	sess.Save(c.Request(), c.Response())
}

func sessDeleteAdministratorID(c echo.Context) {
	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
	}
	delete(sess.Values, "administrator_id")
	sess.Save(c.Request(), c.Response())
}

func loginRequired(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if _, err := getLoginUser(c); err != nil {
			return resError(c, "login_required", 401)
		}
		return next(c)
	}
}

func adminLoginRequired(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if _, err := getLoginAdministrator(c); err != nil {
			return resError(c, "admin_login_required", 401)
		}
		return next(c)
	}
}

func getLoginUser(c echo.Context) (*User, error) {
	userID := sessUserID(c)
	if userID == 0 {
		return nil, errors.New("not logged in")
	}
	u, ok := users[userID]
	if !ok {
		return nil, fmt.Errorf("User not found: %v", userID)
	}
	return u, nil
}

func getLoginAdministrator(c echo.Context) (*Administrator, error) {
	administratorID := sessAdministratorID(c)
	if administratorID == 0 {
		return nil, errors.New("not logged in")
	}
	var administrator Administrator
	err := db.QueryRow("SELECT id, nickname FROM administrators WHERE id = ?", administratorID).Scan(&administrator.ID, &administrator.Nickname)
	return &administrator, err
}

func fetchEvents(all bool) ([]*Event, error) {
	rows, err := db.Query("SELECT * FROM events ORDER BY id ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		var event Event
		if err := rows.Scan(&event.ID, &event.Title, &event.PublicFg, &event.ClosedFg, &event.Price); err != nil {
			return nil, err
		}
		if !all && !event.PublicFg {
			continue
		}
		events = append(events, &event)
	}
	return events, nil
}

func getEvents(all bool) ([]*Event, error) {
	events, err := fetchEvents(all)
	if err != nil {
		return nil, err
	}

	for i, v := range events {
		event, err := getEventSimple(v.ID, -1, v)
		if err != nil {
			return nil, err
		}
		events[i] = event
	}
	return events, nil
}

func getEventsDetail(userID int64) ([]*Event, error) {
	events, err := fetchEvents(true)
	if err != nil {
		return nil, err
	}

	for i, v := range events {
		event, err := getEvent(v.ID, userID, v)
		if err != nil {
			return nil, err
		}
		events[i] = event
	}
	return events, nil
}

func sheetInfo(id int64) Sheet {
	switch {
	case id <= 50:
		return Sheet{ID: id, Rank: "S", Num: id, Price: 5000}
	case id <= 200:
		return Sheet{ID: id, Rank: "A", Num: id - 50, Price: 3000}
	case id <= 500:
		return Sheet{ID: id, Rank: "B", Num: id - 200, Price: 1000}
	default:
		return Sheet{ID: id, Rank: "C", Num: id - 500, Price: 0}
	}
}

func getEvent(eventID, loginUserID int64, ev *Event) (*Event, error) {
	var event Event
	if ev == nil {
		if err := db.QueryRow("SELECT * FROM events WHERE id = ?", eventID).Scan(&event.ID, &event.Title, &event.PublicFg, &event.ClosedFg, &event.Price); err != nil {
			return nil, err
		}
	} else {
		event = *ev
	}
	event.Sheets = map[string]*Sheets{
		"S": &Sheets{Total: 50, Remains: 50, Price: 5000 + event.Price},
		"A": &Sheets{Total: 150, Remains: 150, Price: 3000 + event.Price},
		"B": &Sheets{Total: 300, Remains: 300, Price: 1000 + event.Price},
		"C": &Sheets{Total: 500, Remains: 500, Price: event.Price},
	}

	reservations, reservedSheets := getReservationForEvent(eventID)
	if len(reservedSheets) == 0 {
		reservedSheets = make([]int64, 1001)
	}

	event.Total = 1000
	event.Remains = 1000 - len(reservations)

	event.Sheets["S"].Detail = make([]Sheet, 50)
	event.Sheets["A"].Detail = make([]Sheet, 150)
	event.Sheets["B"].Detail = make([]Sheet, 300)
	event.Sheets["C"].Detail = make([]Sheet, 500)

	for sheetID := 1; sheetID <= 1000; sheetID++ {
		sheet := sheetInfo(int64(sheetID))
		event.Sheets[sheet.Rank].Detail[sheet.Num-1] = sheet
	}

	for _, r := range reservations {
		sheet := sheetInfo(r.SheetID)
		sheet.Mine = reservedSheets[r.SheetID] == loginUserID
		sheet.Reserved = true
		sheet.ReservedAtUnix = r.ReservedAt.Unix()

		ss := event.Sheets[sheet.Rank]
		ss.Remains--
		ss.Detail[sheet.Num-1] = sheet
	}

	return &event, nil
}

func getEventSimple(eventID, loginUserID int64, ev *Event) (*Event, error) {
	var event Event
	if ev == nil {
		if err := db.QueryRow("SELECT * FROM events WHERE id = ?", eventID).Scan(&event.ID, &event.Title, &event.PublicFg, &event.ClosedFg, &event.Price); err != nil {
			return nil, err
		}
	} else {
		event = *ev
	}
	event.Sheets = map[string]*Sheets{
		"S": &Sheets{},
		"A": &Sheets{},
		"B": &Sheets{},
		"C": &Sheets{},
	}

	reservations, reservedSheets := getReservationForEvent(eventID)
	if len(reservedSheets) == 0 {
		reservedSheets = make([]int64, 1001)
	}

	reservedAtMap := make(map[int64]int64)
	for _, r := range reservations {
		reservedAtMap[r.SheetID] = r.ReservedAt.Unix()
	}

	var sheetID int64
	for sheetID = 1; sheetID <= 1000; sheetID++ {
		sheet := sheetInfo(sheetID)
		event.Sheets[sheet.Rank].Price = event.Price + sheet.Price
		event.Total++
		event.Sheets[sheet.Rank].Total++

		if reservedSheets[sheetID] != 0 {
			sheet.Mine = reservedSheets[sheetID] == loginUserID
			sheet.Reserved = true
			sheet.ReservedAtUnix = reservedAtMap[sheetID]
		} else {
			event.Remains++
			event.Sheets[sheet.Rank].Remains++
		}
	}

	return &event, nil
}

func sanitizeEvent(e *Event) *Event {
	sanitized := *e
	sanitized.Price = 0
	sanitized.PublicFg = false
	sanitized.ClosedFg = false
	return &sanitized
}

func fillinUser(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if user, err := getLoginUser(c); err == nil {
			c.Set("user", user)
		}
		return next(c)
	}
}

func fillinAdministrator(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if administrator, err := getLoginAdministrator(c); err == nil {
			c.Set("administrator", administrator)
		}
		return next(c)
	}
}

func validateRank(rank string) bool {
	switch rank {
	case "S", "A", "B", "C":
		return true
	default:
		return false
	}
}

type Renderer struct {
	templates *template.Template
}

func (r *Renderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return r.templates.ExecuteTemplate(w, name, data)
}

var db *sql.DB

func initdb() {
	if db != nil {
		db.Close()
		db = nil
	}
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4&interpolateParams=true",
		os.Getenv("DB_USER"), os.Getenv("DB_PASS"),
		os.Getenv("DB_HOST"), os.Getenv("DB_PORT"),
		os.Getenv("DB_DATABASE"),
	)

	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(400)
	db.SetConnMaxLifetime(time.Minute * 2)

	for {
		err := db.Ping()
		if err == nil {
			break
		}
		log.Printf("Failed to PING db: %v", err)
		time.Sleep(time.Second * 5)
	}
}

func selectUserReservations(userID int64) ([]Reservation, error) {
	rows, err := db.Query("SELECT * FROM reservations WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rs []Reservation
	for rows.Next() {
		var reservation Reservation
		if err := rows.Scan(&reservation.ID, &reservation.EventID, &reservation.SheetID, &reservation.UserID, &reservation.ReservedAt, &reservation.CanceledAt); err != nil {
			return nil, err
		}
		rs = append(rs, reservation)
	}

	return rs, nil
}

// /api/users/:id
func get_api_user_id(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return err
	}
	user, ok := users[int64(id)]
	if !ok {
		return fmt.Errorf("user not found: %d", id)
	}

	loginUser, err := getLoginUser(c)
	if err != nil {
		return err
	}
	if user.ID != loginUser.ID {
		return resError(c, "forbidden", 403)
	}

	reservations, err := selectUserReservations(user.ID)
	sort.Slice(reservations, func(i, j int) bool {
		l := reservations[i].CanceledAt
		if l == nil {
			l = reservations[i].ReservedAt
		}

		r := reservations[j].CanceledAt
		if r == nil {
			r = reservations[j].ReservedAt
		}

		return l.After(*r)
	})
	cr := len(reservations)
	if cr > 5 {
		cr = 5
	}
	recentReservations := make([]Reservation, cr)
	copy(recentReservations, reservations)

	events, err := getEventsDetail(user.ID)
	if err != nil {
		return err
	}
	eventMap := make(map[int64]*Event)
	for _, e := range events {
		eventMap[e.ID] = e
	}

	for i := range recentReservations {
		pr := recentReservations[i]
		event := *eventMap[pr.EventID]
		sheet := sheetInfo(pr.SheetID)
		price := event.Sheets[sheet.Rank].Price
		event.Sheets = nil
		event.Total = 0
		event.Remains = 0

		pr.Event = &event
		pr.SheetRank = sheet.Rank
		pr.SheetNum = sheet.Num
		pr.Price = price
		pr.ReservedAtUnix = pr.ReservedAt.Unix()
		if pr.CanceledAt != nil {
			pr.CanceledAtUnix = pr.CanceledAt.Unix()
		}
		recentReservations[i] = pr
	}

	var totalPrice int
	for _, r := range reservations {
		if r.CanceledAt == nil {
			continue
		}
		event := eventMap[r.EventID]
		sheet := sheetInfo(r.SheetID)
		if event == nil {
			log.Printf("Unknown event id: %v in reservation %#v", r.EventID, r)
			continue
		}
		if event.Sheets == nil {
			panic("nil sheets")
		}
		if event.Sheets[sheet.Rank] == nil {
			panic("nil sheets rank")
		}
		totalPrice += int(event.Sheets[sheet.Rank].Price)
	}

	var recentEvents []*Event = []*Event{}
	for _, r := range reservations {
		eid := r.EventID
		found := false
		for _, e := range recentEvents {
			if e.ID == eid {
				found = true
				break
			}
		}
		if !found {
			e := eventMap[eid]
			var ee Event = *e // カスタマイズのためにコピーを作る
			ee.Sheets = make(map[string]*Sheets)
			for k, v := range e.Sheets {
				s := *v
				s.Detail = nil
				ee.Sheets[k] = &s
			}
			recentEvents = append(recentEvents, &ee)
			if len(recentEvents) >= 5 {
				break
			}
		}
	}

	return c.JSON(200, echo.Map{
		"id":                  user.ID,
		"nickname":            user.Nickname,
		"recent_reservations": recentReservations,
		"total_price":         totalPrice,
		"recent_events":       recentEvents,
	})
}

func validateEvent(eventID int64) (bool, error) {
	//var f bool
	//err := db.QueryRow("SELECT public_fg from events WHERE ID=?", eventID).Scan(&f)
	//return f, err
	eventLock.Lock()
	pub, ok := eventOk[eventID]
	eventLock.Unlock()

	var err error = nil
	if !ok {
		err = sql.ErrNoRows
	}
	return pub, err
}

func main() {
	var err error
	initdb()
	initReservation()
	resetEvents()

	e := echo.New()
	funcs := template.FuncMap{
		"encode_json": func(v interface{}) string {
			b, _ := json.Marshal(v)
			return string(b)
		},
	}
	e.Renderer = &Renderer{
		templates: template.Must(template.New("").Delims("[[", "]]").Funcs(funcs).ParseGlob("views/*.tmpl")),
	}
	e.Use(session.Middleware(sessions.NewCookieStore([]byte("secret"))))
	//e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{Output: os.Stderr}))
	e.Static("/", "public")

	var eventCache zerotimecache.Cache
	e.GET("/", func(c echo.Context) error {
		events, err := eventCache.DoDelay(time.Millisecond*50, func() (interface{}, error) {
			events, err := getEvents(false)
			if err != nil {
				return nil, err
			}
			for i, v := range events {
				events[i] = sanitizeEvent(v)
			}
			js, _ := json.Marshal(events)
			return string(js), nil
		})
		if err != nil {
			return err
		}

		return c.Render(200, "index.tmpl", echo.Map{
			"events": events.(string),
			"user":   c.Get("user"),
			"origin": c.Scheme() + "://" + c.Request().Host,
		})
	}, fillinUser)
	e.GET("/initialize", func(c echo.Context) error {
		cmd := exec.Command("../../db/init.sh")
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		err := cmd.Run()
		if err != nil {
			return nil
		}

		//initdb()
		initReservation()
		resetEvents()

		//if err := StartProfile(time.Minute); err != nil {
		//	log.Printf("failed to start profile; %v", err)
		//}

		users = make(map[int64]*User)
		usersName = make(map[string]*User)
		rows, err := db.Query("SELECT id, nickname, login_name, pass_hash FROM users")
		if err != nil {
			fmt.Println(err)
			return c.NoContent(500)
		}
		defer rows.Close()
		for rows.Next() {
			var u User
			if err := rows.Scan(&u.ID, &u.Nickname, &u.LoginName, &u.PassHash); err != nil {
				fmt.Println(err)
				return c.NoContent(500)
			}
			users[u.ID] = &u
			usersName[u.LoginName] = &u
		}

		return c.NoContent(204)
	})
	e.POST("/api/users", func(c echo.Context) error {
		var params struct {
			Nickname  string `json:"nickname"`
			LoginName string `json:"login_name"`
			Password  string `json:"password"`
		}
		c.Bind(&params)

		userLock.Lock()
		defer userLock.Unlock()
		user, ok := usersName[params.LoginName]
		if ok {
			return resError(c, "duplicated", 409)
		}

		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(params.Password)))

		res, err := db.Exec("INSERT INTO users (login_name, pass_hash, nickname) VALUES (?, ?, ?)", params.LoginName, hash, params.Nickname)
		if err != nil {
			return resError(c, "insert fail", 0)
		}
		userID, err := res.LastInsertId()
		if err != nil {
			return resError(c, "unknown id", 0)
		}
		user = &User{userID, params.Nickname, params.LoginName, hash}
		users[userID] = user
		usersName[params.LoginName] = user

		return c.JSON(201, echo.Map{
			"id":       userID,
			"nickname": params.Nickname,
		})
	})
	e.GET("/api/users/:id", get_api_user_id, loginRequired)
	e.POST("/api/actions/login", func(c echo.Context) error {
		var params struct {
			LoginName string `json:"login_name"`
			Password  string `json:"password"`
		}
		c.Bind(&params)

		user, ok := usersName[params.LoginName]
		if !ok {
			return resError(c, "authentication_failed", 401)
		}

		passHash := fmt.Sprintf("%x", sha256.Sum256([]byte(params.Password)))
		if user.PassHash != passHash {
			return resError(c, "authentication_failed", 401)
		}

		sessSetUserID(c, user.ID)
		user, err = getLoginUser(c)
		if err != nil {
			return err
		}
		return c.JSON(200, user)
	})
	e.POST("/api/actions/logout", func(c echo.Context) error {
		sessDeleteUserID(c)
		return c.NoContent(204)
	}, loginRequired)
	e.GET("/api/events", func(c echo.Context) error {
		events, err := getEvents(true)
		if err != nil {
			return err
		}
		for i, v := range events {
			events[i] = sanitizeEvent(v)
		}
		return c.JSON(200, events)
	})
	e.GET("/api/events/:id", func(c echo.Context) error {
		time.Sleep(time.Millisecond * 20)
		eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return resError(c, "not_found", 404)
		}

		loginUserID := int64(-1)
		if user, err := getLoginUser(c); err == nil {
			loginUserID = user.ID
		}

		event, err := getEvent(eventID, loginUserID, nil)
		if err != nil {
			if err == sql.ErrNoRows {
				return resError(c, "not_found", 404)
			}
			return err
		} else if !event.PublicFg {
			return resError(c, "not_found", 404)
		}
		return c.JSON(200, sanitizeEvent(event))
	})
	e.POST("/api/events/:id/actions/reserve", func(c echo.Context) error {
		eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return resError(c, "not_found", 404)
		}
		var params struct {
			Rank string `json:"sheet_rank"`
		}
		c.Bind(&params)

		user, err := getLoginUser(c)
		if err != nil {
			return err
		}

		public, err := validateEvent(eventID)
		if err != nil {
			if err == sql.ErrNoRows {
				return resError(c, "invalid_event", 404)
			}
			log.Println(err)
			return err
		} else if !public {
			return resError(c, "invalid_event", 404)
		}

		if !validateRank(params.Rank) {
			return resError(c, "invalid_rank", 400)
		}

		reservationID, sheetNum, err := doReserve(eventID, user.ID, params.Rank)
		if err == FullReserved {
			return resError(c, "sold_out", 409)
		} else if err != nil {
			return err
		}

		return c.JSON(202, echo.Map{
			"id":         reservationID,
			"sheet_rank": params.Rank,
			"sheet_num":  sheetNum,
		})
	}, loginRequired)
	e.DELETE("/api/events/:id/sheets/:rank/:num/reservation", func(c echo.Context) error {
		eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return resError(c, "not_found", 404)
		}
		rank := c.Param("rank")
		num := c.Param("num")

		user, err := getLoginUser(c)
		if err != nil {
			return err
		}

		public, err := validateEvent(eventID)
		if err != nil {
			if err == sql.ErrNoRows {
				return resError(c, "invalid_event", 404)
			}
			log.Println(err)
			return err
		} else if !public {
			return resError(c, "invalid_event", 404)
		}

		if !validateRank(rank) {
			return resError(c, "invalid_rank", 404)
		}

		sheetNum, err := strconv.Atoi(num)
		if err != nil {
			return resError(c, "invalid_num", 404)
		}
		var maxSheetNum int
		switch rank {
		case "S":
			maxSheetNum = 50
		case "A":
			maxSheetNum = 150
		case "B":
			maxSheetNum = 300
		case "C":
			maxSheetNum = 500
		default:
			return resError(c, "invalid_rank", 404)
		}
		if sheetNum > maxSheetNum {
			return resError(c, "invalid_sheet", 404)
		}

		err = cancelReservation(eventID, int64(sheetNum), user.ID, rank)
		if err == NotReserved {
			return resError(c, "not_reserved", 400)
		}
		if err == NotOwner {
			log.Printf("DELETE rank=%v, num=%v", rank, num)
			return resError(c, "not_permitted", 403)
		}
		if err != nil {
			return err
		}

		return c.NoContent(204)
	}, loginRequired)
	e.GET("/admin/", func(c echo.Context) error {
		var events []*Event
		administrator := c.Get("administrator")
		if administrator != nil {
			var err error
			if events, err = getEvents(true); err != nil {
				return err
			}
		}
		return c.Render(200, "admin.tmpl", echo.Map{
			"events":        events,
			"administrator": administrator,
			"origin":        c.Scheme() + "://" + c.Request().Host,
		})
	}, fillinAdministrator)
	e.POST("/admin/api/actions/login", func(c echo.Context) error {
		var params struct {
			LoginName string `json:"login_name"`
			Password  string `json:"password"`
		}
		c.Bind(&params)

		administrator := new(Administrator)
		if err := db.QueryRow("SELECT * FROM administrators WHERE login_name = ?", params.LoginName).Scan(&administrator.ID, &administrator.LoginName, &administrator.Nickname, &administrator.PassHash); err != nil {
			if err == sql.ErrNoRows {
				return resError(c, "authentication_failed", 401)
			}
			return err
		}

		var passHash string
		if err := db.QueryRow("SELECT SHA2(?, 256)", params.Password).Scan(&passHash); err != nil {
			return err
		}
		if administrator.PassHash != passHash {
			return resError(c, "authentication_failed", 401)
		}

		sessSetAdministratorID(c, administrator.ID)
		administrator, err = getLoginAdministrator(c)
		if err != nil {
			return err
		}
		return c.JSON(200, administrator)
	})
	e.POST("/admin/api/actions/logout", func(c echo.Context) error {
		sessDeleteAdministratorID(c)
		return c.NoContent(204)
	}, adminLoginRequired)
	e.GET("/admin/api/events", func(c echo.Context) error {
		events, err := getEvents(true)
		if err != nil {
			return err
		}
		return c.JSON(200, events)
	}, adminLoginRequired)
	e.POST("/admin/api/events", func(c echo.Context) error {
		var params struct {
			Title  string `json:"title"`
			Public bool   `json:"public"`
			Price  int    `json:"price"`
		}
		c.Bind(&params)

		res, err := db.Exec("INSERT INTO events (title, public_fg, closed_fg, price) VALUES (?, ?, 0, ?)", params.Title, params.Public, params.Price)
		if err != nil {
			return err
		}
		eventID, err := res.LastInsertId()
		if err != nil {
			return err
		}

		eventLock.Lock()
		eventOk[eventID] = params.Public
		eventLock.Unlock()

		event, err := getEvent(eventID, -1, nil)
		if err != nil {
			return err
		}
		return c.JSON(200, event)
	}, adminLoginRequired)
	e.GET("/admin/api/events/:id", func(c echo.Context) error {
		eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return resError(c, "not_found", 404)
		}
		event, err := getEvent(eventID, -1, nil)
		if err != nil {
			if err == sql.ErrNoRows {
				return resError(c, "not_found", 404)
			}
			return err
		}
		return c.JSON(200, event)
	}, adminLoginRequired)
	e.POST("/admin/api/events/:id/actions/edit", func(c echo.Context) error {
		eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return resError(c, "not_found", 404)
		}

		var params struct {
			Public bool `json:"public"`
			Closed bool `json:"closed"`
		}
		c.Bind(&params)
		if params.Closed {
			params.Public = false
		}

		event, err := getEvent(eventID, -1, nil)
		if err != nil {
			if err == sql.ErrNoRows {
				return resError(c, "not_found", 404)
			}
			return err
		}

		if event.ClosedFg {
			return resError(c, "cannot_edit_closed_event", 400)
		} else if event.PublicFg && params.Closed {
			return resError(c, "cannot_close_public_event", 400)
		}

		if _, err := db.Exec("UPDATE events SET public_fg = ?, closed_fg = ? WHERE id = ?", params.Public, params.Closed, event.ID); err != nil {
			return err
		}

		eventLock.Lock()
		eventOk[event.ID] = params.Public
		eventLock.Unlock()

		e, err := getEvent(eventID, -1, nil)
		if err != nil {
			return err
		}
		c.JSON(200, e)
		return nil
	}, adminLoginRequired)
	e.GET("/admin/api/reports/events/:id/sales", func(c echo.Context) error {
		eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return resError(c, "not_found", 404)
		}

		event, err := getEvent(eventID, -1, nil)
		if err != nil {
			return err
		}

		rows, err := db.Query("SELECT r.*, s.rank AS sheet_rank, s.num AS sheet_num, s.price AS sheet_price, e.price AS event_price FROM reservations r INNER JOIN sheets s ON s.id = r.sheet_id INNER JOIN events e ON e.id = r.event_id WHERE r.event_id = ? ORDER BY reserved_at ASC", event.ID)
		if err != nil {
			return err
		}
		defer rows.Close()

		var reports []Report
		for rows.Next() {
			var reservation Reservation
			var sheet Sheet
			if err := rows.Scan(&reservation.ID, &reservation.EventID, &reservation.SheetID, &reservation.UserID, &reservation.ReservedAt, &reservation.CanceledAt, &sheet.Rank, &sheet.Num, &sheet.Price, &event.Price); err != nil {
				return err
			}
			report := Report{
				ReservationID: reservation.ID,
				EventID:       event.ID,
				Rank:          sheet.Rank,
				Num:           sheet.Num,
				UserID:        reservation.UserID,
				SoldAt:        reservation.ReservedAt.Format("2006-01-02T15:04:05.000000Z"),
				Price:         event.Price + sheet.Price,
			}
			if reservation.CanceledAt != nil {
				report.CanceledAt = reservation.CanceledAt.Format("2006-01-02T15:04:05.000000Z")
			}
			reports = append(reports, report)
		}
		c.Response().Header().Set("Content-Type", `text/csv; charset=UTF-8`)
		c.Response().Header().Set("Content-Disposition", `attachment; filename="report.csv"`)
		renderReportCSV(reports, c.Response())
		return nil
	}, adminLoginRequired)
	var salesG = singleflight.Group{}
	e.GET("/admin/api/reports/sales", func(c echo.Context) error {
		reportI, err, _ := salesG.Do("", makeReport2)
		if err != nil {
			return err
		}
		reportB := reportI.([]byte)

		c.Response().Header().Set("Content-Type", `text/csv; charset=UTF-8`)
		c.Response().Header().Set("Content-Disposition", `attachment; filename="report.csv"`)
		//c.Response().Header().Set("Content-Encoding", "gzip")
		c.Response().Write(reportB)
		return nil
	}, adminLoginRequired)

	e.GET("/debug/report1", func(c echo.Context) error {
		reportI, err, _ := salesG.Do("", makeReport)
		if err != nil {
			return err
		}
		reportB := reportI.([]byte)

		c.Response().Header().Set("Content-Type", `text/csv; charset=UTF-8`)
		c.Response().Header().Set("Content-Disposition", `attachment; filename="report.csv"`)
		//c.Response().Header().Set("Content-Encoding", "gzip")
		c.Response().Write(reportB)
		return nil
	})

	e.GET("/debug/report2", func(c echo.Context) error {
		reportI, err, _ := salesG.Do("", makeReport2)
		if err != nil {
			return err
		}
		reportB := reportI.([]byte)

		c.Response().Header().Set("Content-Type", `text/csv; charset=UTF-8`)
		c.Response().Header().Set("Content-Disposition", `attachment; filename="report.csv"`)
		//c.Response().Header().Set("Content-Encoding", "gzip")
		c.Response().Write(reportB)
		return nil
	})

	os.Remove("/tmp/torb.sock")
	ln, err := net.Listen("unix", "/tmp/torb.sock")
	if err != nil {
		panic(err)
	}
	e.Listener = ln
	log.Print(os.Chmod("/tmp/torb.sock", 0777))
	log.Print(e.Start(""))
	//log.Print(e.Start(":8080"))
}

type Report struct {
	ReservationID int64
	EventID       int64
	Rank          string
	Num           int64
	UserID        int64
	SoldAt        string
	CanceledAt    string
	Price         int64
}

func makeReport2() (interface{}, error) {
	time.Sleep(time.Millisecond * 300)

	UpdateReport()

	mReport.Lock()
	buf := bytes.Buffer{}
	buf.WriteString("reservation_id,event_id,rank,num,price,user_id,sold_at,canceled_at\n")
	for _, rc := range reportData {
		buf.WriteString(rc.Rendered)
	}
	mReport.Unlock()

	return buf.Bytes(), nil
}

func makeReport() (interface{}, error) {
	time.Sleep(time.Millisecond * 100)
	stmt, err := db.Prepare("select r.*, e.id as event_id, e.price as event_price from reservations r inner join events e on e.id = r.event_id")
	if err != nil {
		return nil, err
	}
	rows, err := stmt.Query()
	defer stmt.Close()
	//rows, err := db.Query("select r.*, e.id as event_id, e.price as event_price from reservations r inner join events e on e.id = r.event_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reports []Report
	for rows.Next() {
		var reservation Reservation
		var event Event
		if err := rows.Scan(&reservation.ID, &reservation.EventID, &reservation.SheetID, &reservation.UserID, &reservation.ReservedAt, &reservation.CanceledAt, &event.ID, &event.Price); err != nil {
			return nil, err
		}
		sheet := sheetInfo(reservation.SheetID)
		report := Report{
			ReservationID: reservation.ID,
			EventID:       event.ID,
			Rank:          sheet.Rank,
			Num:           sheet.Num,
			UserID:        reservation.UserID,
			SoldAt:        reservation.ReservedAt.Format("2006-01-02T15:04:05.000000Z"),
			Price:         event.Price + sheet.Price,
		}
		if reservation.CanceledAt != nil {
			report.CanceledAt = reservation.CanceledAt.Format("2006-01-02T15:04:05.000000Z")
		}
		reports = append(reports, report)
	}
	buf := bytes.Buffer{}
	//w, _ := gzip.NewWriterLevel(&buf, 3)
	renderReportCSV(reports, &buf)
	//w.Close()
	return buf.Bytes(), nil
}

func renderReportCSV(reports []Report, w io.Writer) {
	sort.Slice(reports, func(i, j int) bool { return strings.Compare(reports[i].SoldAt, reports[j].SoldAt) < 0 })

	body := bytes.NewBufferString("reservation_id,event_id,rank,num,price,user_id,sold_at,canceled_at\n")
	for _, v := range reports {
		body.WriteString(fmt.Sprintf("%d,%d,%s,%d,%d,%d,%s,%s\n",
			v.ReservationID, v.EventID, v.Rank, v.Num, v.Price, v.UserID, v.SoldAt, v.CanceledAt))
	}
	body.WriteTo(w)
}

func resError(c echo.Context, e string, status int) error {
	if e == "" {
		e = "unknown"
	}
	if status < 100 {
		status = 500
	}
	return c.JSON(status, map[string]string{"error": e})
}

func resetEvents() {
	rows, err := db.Query("SELECT id, public_fg from events")
	for err != nil {
		rows, err = db.Query("SELECT id, public_fg from events")
	}
	defer rows.Close()

	eventLock.Lock()
	eventOk = make(map[int64]bool)

	for rows.Next() {
		var i int64
		var b bool
		rows.Scan(&i, &b)
		eventOk[i] = b
	}
	eventLock.Unlock()
}
