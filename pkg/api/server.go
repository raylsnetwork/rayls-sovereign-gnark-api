package api

import (
	"github.com/raylsnetwork/rayls-sovereign-gnark-api/config"
	deposit "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-payments/enygma-deposit"
	transfer "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-payments/enygma-transfer"
	withdraw "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-payments/enygma-withdraw"

	enygma_joinsplit "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-dvp/enygma-joinsplit-dvp"
	erc1155_joinsplit "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-dvp/erc1155-joinsplit-dvp"
	erc721_ownership "github.com/raylsnetwork/rayls-sovereign-gnark-api/pkg/circuits/enygma/enygma-dvp/erc721-ownership-dvp"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func NewServer(cfg *config.Config) *gin.Engine {
	r := gin.Default()

	// Health check endpoint
	r.GET("/healthcheck", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"message": "Server is healthy",
		})
	})

	// Dynamic Transfer handler
	r.POST("/generateProofTransfer-:k", func(c *gin.Context) {
		k, err := strconv.Atoi(c.Param("k"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid k parameter: must be a number",
			})
			return
		}

		if k < 2 || k > 6 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "k value not supported: must be between 2 and 6",
			})
			return
		}

		// Get the appropriate config values based on k
		pkPath, vkPath, r1csPath := getTransferConfig(cfg, k)
		if pkPath == "" {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Configuration not found for k=" + strconv.Itoa(k),
			})
			return
		}

		// Call the transfer handler
		handler := transfer.NewHandler(k, pkPath, vkPath, r1csPath)
		handler(c)
	})

	// Dynamic Withdraw handler
	r.POST("/generateProofWithdraw-:k", func(c *gin.Context) {
		k, err := strconv.Atoi(c.Param("k"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid k parameter: must be a number",
			})
			return
		}

		if k < 2 || k > 6 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "k value not supported: must be between 2 and 6",
			})
			return
		}

		// Get the appropriate config values based on k
		pkPath, vkPath, r1csPath := getWithdrawConfig(cfg, k)
		if pkPath == "" {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Configuration not found for k=" + strconv.Itoa(k),
			})
			return
		}

		// Call the withdraw handler
		handler := withdraw.NewHandler(k, pkPath, vkPath, r1csPath)
		handler(c)
	})

	// Dynamic Deposit handler
	r.POST("/generateProofDeposit-:k", func(c *gin.Context) {
		k, err := strconv.Atoi(c.Param("k"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid k parameter: must be a number",
			})
			return
		}

		if k < 2 || k > 6 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "k value not supported: must be between 2 and 6",
			})
			return
		}

		// Get the appropriate config values based on k
		pkPath, vkPath, r1csPath := getDepositConfig(cfg, k)
		if pkPath == "" {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Configuration not found for k=" + strconv.Itoa(k),
			})
			return
		}

		// Call the deposit handler
		handler := deposit.NewHandler(k, pkPath, vkPath, r1csPath)
		handler(c)
	})

	// Join-Split Enygma handler
	r.POST("/join-split-enygma", func(c *gin.Context) {
		pkPath := cfg.EnygmaJoinSplitPk
		vkPath := cfg.EnygmaJoinSplitVk
		r1csPath := cfg.EnygmaJoinSplitR1cs
		handler := enygma_joinsplit.NewHandler(pkPath, vkPath, r1csPath)
		handler(c)
	})

	// Erc-721 Ownership handler
	r.POST("/ownership-721", func(c *gin.Context) {
		pkPath := cfg.Erc721OwnershipPk
		vkPath := cfg.Erc721OwnershipVk
		r1csPath := cfg.Erc721OwnershipR1cs
		handler := erc721_ownership.NewHandler(pkPath, vkPath, r1csPath)
		handler(c)
	})

	// Erc-1155 Join-Split handler
	r.POST("/join-split-1155", func(c *gin.Context) {
		pkPath := cfg.Erc1155JoinSplitPk
		vkPath := cfg.Erc1155JoinSplitVk
		r1csPath := cfg.Erc1155JoinSplitR1cs
		handler := erc1155_joinsplit.NewHandler(pkPath, vkPath, r1csPath)
		handler(c)
	})

	return r
}

// Helper function to get transfer configuration based on k value
func getTransferConfig(cfg *config.Config, k int) (string, string, string) {
	switch k {
	case 2:
		return cfg.Enygmak2Pk, cfg.Enygmak2Vk, cfg.Enygmak2R1cs
	case 3:
		return cfg.Enygmak3Pk, cfg.Enygmak3Vk, cfg.Enygmak3R1cs
	case 4:
		return cfg.Enygmak4Pk, cfg.Enygmak4Vk, cfg.Enygmak4R1cs
	case 5:
		return cfg.Enygmak5Pk, cfg.Enygmak5Vk, cfg.Enygmak5R1cs
	case 6:
		return cfg.Enygmak6Pk, cfg.Enygmak6Vk, cfg.Enygmak6R1cs
	default:
		return "", "", ""
	}
}

// Helper function to get withdraw configuration based on k value
func getWithdrawConfig(cfg *config.Config, k int) (string, string, string) {
	switch k {
	case 2:
		return cfg.Withdrawk2Pk, cfg.Withdrawk2Vk, cfg.Withdrawk2R1cs
	case 3:
		return cfg.Withdrawk3Pk, cfg.Withdrawk3Vk, cfg.Withdrawk3R1cs
	case 4:
		return cfg.Withdrawk4Pk, cfg.Withdrawk4Vk, cfg.Withdrawk4R1cs
	case 5:
		return cfg.Withdrawk5Pk, cfg.Withdrawk5Vk, cfg.Withdrawk5R1cs
	case 6:
		return cfg.Withdrawk6Pk, cfg.Withdrawk6Vk, cfg.Withdrawk6R1cs
	default:
		return "", "", ""
	}
}

// Helper function to get deposit configuration based on k value
func getDepositConfig(cfg *config.Config, k int) (string, string, string) {
	switch k {
	case 2:
		return cfg.Depositk2Pk, cfg.Depositk2Vk, cfg.Depositk2R1cs
	case 3:
		return cfg.Depositk3Pk, cfg.Depositk3Vk, cfg.Depositk3R1cs
	case 4:
		return cfg.Depositk4Pk, cfg.Depositk4Vk, cfg.Depositk4R1cs
	case 5:
		return cfg.Depositk5Pk, cfg.Depositk5Vk, cfg.Depositk5R1cs
	case 6:
		return cfg.Depositk6Pk, cfg.Depositk6Vk, cfg.Depositk6R1cs
	default:
		return "", "", ""
	}
}
