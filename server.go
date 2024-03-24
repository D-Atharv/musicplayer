package main

import (
	"log"
	"time"

	"github.com/MP/model"
	database "github.com/MP/src"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/template/html/v2"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

var store = session.New()

func init() {

	if err := godotenv.Load(".env"); err != nil {
		log.Fatal("Error in loading .env file")
	}
	//connecting database
	database.ConnectDB()
}

func main() {

	sqlDb, err := database.DBConn.DB()

	if err != nil {
		panic("Error in sql connection.")
	}

	defer sqlDb.Close()

	//template engine
	template_engine := html.New(
		"./views",
		".html",
	)

	// start fiber
	app := fiber.New(fiber.Config{
		Views: template_engine,
	})

	// add static folder -> to use css
	app.Static(
		"/static",  // mount address
		"./public", // path to the file folder
	)

	//login page
	app.Get("/login", func(c *fiber.Ctx) error {
		return c.Render("login", nil)
	})

	//Redirect to Login Page
	app.Get("/", func(c *fiber.Ctx) error {
		return c.Redirect("login")
	})

	//Signup Page
	app.Get("/signup", func(c *fiber.Ctx) error {
		return c.Render("signup", nil)
	})

	//SIGNUP WITH BCRYPT
	app.Post("/signup", func(c *fiber.Ctx) error {
		// Parse request body into User struct
		var user model.User
		if err := c.BodyParser(&user); err != nil {
			log.Println("Error in parsing request:", err)
			return c.Status(400).JSON(fiber.Map{
				"statusText": "Error",
				"Message":    "Invalid request format",
			})
		}

		// checking if user already exists
		var existingUser model.User
		if err := database.DBConn.Where("name = ?", user.Name).First(&existingUser).Error; err == nil {
			log.Println("User already exists")
			// Render a signup page
			return c.Render("signup", fiber.Map{
				"AlertMessage": "User already exists",
			})
		}

		// Hashing the password with salt
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Println("Error hashing password:", err)
			return c.Status(500).JSON(fiber.Map{
				"statusText": "Error",
				"Message":    "Failed to hash password",
			})
		}

		// Saving the data to datbase
		user.Password = string(hashedPassword)
		if err := database.DBConn.Create(&user).Error; err != nil {
			log.Println("Error creating user:", err)
			return c.Status(500).JSON(fiber.Map{
				"statusText": "Error",
				"Message":    "Failed to create user",
			})
		}

		log.Println("User created successfully")
		return c.Status(201).Redirect("/login")
	})

	//LOGIN TO HOMEPAGE
	app.Post("/login", func(c *fiber.Ctx) error {
		// Parse request body for username and password
		var loginData struct {
			Username string `json:"name"`
			Password string `json:"password"`
		}
		if err := c.BodyParser(&loginData); err != nil {
			log.Println("Error parsing login request:", err)
			return c.Status(400).JSON(fiber.Map{
				"statusText": "Error",
				"message":    "Invalid request format",
			})
		}

		// finding user based on username
		var user model.User
		if err := database.DBConn.Where("name = ?", loginData.Username).First(&user).Error; err != nil {
			log.Println("User not found:", err)
			return c.Render("login", fiber.Map{
				"AlertMessage": "User not found",
			})
		}

		// checking if password is same
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password)); err != nil {
			log.Println("Incorrect password:", err)
			return c.Render("login", fiber.Map{
				"AlertMessage": "Incorrect password",
			})
		}

		// Passwords match, login successful
		log.Println("Login successful")

		// if login is successfull--->
		sess, err := store.Get(c)
		if err != nil {
			log.Println("Session error:", err)
			return c.SendStatus(fiber.StatusInternalServerError)
		}

		sess.Set("userID", user.ID)
		sess.Set("authenticated", true)

		// Save the session.
		if err := sess.Save(); err != nil {
			log.Println("Error saving session:", err)
			return c.SendStatus(fiber.StatusInternalServerError)
		}
		return c.Redirect("/home")
	})

	//Home page rendering
	app.Get("/home", func(c *fiber.Ctx) error {
		if !isAuthenticated(c) {
			return c.Redirect("/login")
		}
		return c.Render("home", nil)
	})

	//logout
	app.Get("/logout", func(c *fiber.Ctx) error {
		sess, err := store.Get(c)
		if err != nil {
			log.Println("Logout session error:", err)
			return c.SendStatus(fiber.StatusInternalServerError)
		}

		// Destroying the session
		if err := sess.Destroy(); err != nil {
			log.Println("Error destroying session:", err)
			return c.SendStatus(fiber.StatusInternalServerError)
		}

		// Clearing the session
		c.Cookie(&fiber.Cookie{
			Name:     "cookie_id",
			Value:    "",
			Expires:  time.Now().Add(-5 * time.Hour),
			HTTPOnly: true,
		})

		return c.Redirect("/login")
	})

	//Listening to server
	app.Listen(":3000")
}

func isAuthenticated(c *fiber.Ctx) bool {
	sess, err := store.Get(c)
	if err != nil {
		return false
	}

	auth, ok := sess.Get("authenticated").(bool)
	return ok && auth
}
