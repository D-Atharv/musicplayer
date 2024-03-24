package main

import (
	"log"

	"github.com/MP/model"
	database "github.com/MP/src"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

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

	// Initialize standard Go html template engine
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
	//not using fiber.Map since no dynamic content in html
	app.Get("/login", func(c *fiber.Ctx) error {
		return c.Render("login", nil)
	})

	//Redirect to Login Page--> HAVE TO CHECK THIS
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

		// Check if user already exists
		var existingUser model.User
		if err := database.DBConn.Where("name = ?", user.Name).First(&existingUser).Error; err == nil {
			log.Println("User already exists")
			// Render a signup page with an alert message
			return c.Render("signup", fiber.Map{
				"AlertMessage": "User already exists",
			})
		}

		// Hash the password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Println("Error hashing password:", err)
			return c.Status(500).JSON(fiber.Map{
				"statusText": "Error",
				"Message":    "Failed to hash password",
			})
		}

		// Save user record to database
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

		// Find user in the database based on username
		var user model.User
		if err := database.DBConn.Where("name = ?", loginData.Username).First(&user).Error; err != nil {
			log.Println("User not found:", err)
			return c.Render("login", fiber.Map{
				"AlertMessage": "User not found",
			})
		}

		// Compare passwords
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password)); err != nil {
			log.Println("Incorrect password:", err)
			return c.Render("login", fiber.Map{
				"AlertMessage": "Incorrect password",
			})
		}

		// Passwords match, login successful
		log.Println("Login successful")
		return c.Render("home", nil) // Render home page
	})

	//Logout Page and Redirect to Login
	app.Get("/logout", func(c *fiber.Ctx) error {
		return c.Redirect("login")
	})

	//Listening to server
	app.Listen(":3000")
}
