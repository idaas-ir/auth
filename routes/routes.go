package routes

import (
	"auth/auth"
	"auth/handlers"

	"github.com/gin-gonic/gin"
	"github.com/gin-contrib/cors"
)

func SetupRouter() *gin.Engine {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"}, // Your frontend URL
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// Public routes
	r.POST("/signup", handlers.CreateProfile)
	r.POST("/signin", handlers.GetProfile)
	r.POST("/refresh", handlers.RefreshToken)

	// Protected routes
	protected := r.Group("/")
	protected.Use(auth.AuthMiddleware())
	{
		protected.PUT("/forget-password", handlers.UpdateProfile)
		protected.POST("/delete-profile", handlers.DeleteProfile)
	}

	return r
}
