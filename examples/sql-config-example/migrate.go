package main

import (
	"log"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/oarkflow/tcpguard"
)

func main() {
	log.Println("Starting migration from JSON to SQL...")

	// Load from JSON files
	fileStore, err := tcpguard.NewFileConfigStore("../configs")
	if err != nil {
		log.Fatal("Failed to load JSON config:", err)
	}

	// Create SQL database
	db, err := sqlx.Connect("sqlite3", "./tcpguard_migrated.db")
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	sqlStore, err := tcpguard.NewSQLConfigStore(db)
	if err != nil {
		log.Fatal("Failed to create SQL store:", err)
	}

	// Migrate global config
	log.Println("Migrating global config...")
	globalConfig, err := fileStore.GetGlobalConfig()
	if err == nil && globalConfig != nil {
		sqlStore.UpdateGlobalConfig(globalConfig)
	}

	// Migrate rules
	log.Println("Migrating rules...")
	rules, err := fileStore.ListRules()
	if err == nil {
		for _, rule := range rules {
			if err := sqlStore.CreateRule(rule); err != nil {
				log.Printf("Warning: Failed to migrate rule %s: %v", rule.Name, err)
			} else {
				log.Printf("  ✓ Migrated rule: %s", rule.Name)
			}
		}
	}

	// Migrate endpoints
	log.Println("Migrating endpoints...")
	endpoints, err := fileStore.ListEndpoints()
	if err == nil {
		for _, ep := range endpoints {
			if err := sqlStore.CreateEndpoint(ep); err != nil {
				log.Printf("Warning: Failed to migrate endpoint %s: %v", ep.Endpoint, err)
			} else {
				log.Printf("  ✓ Migrated endpoint: %s", ep.Endpoint)
			}
		}
	}

	// Migrate users
	log.Println("Migrating users...")
	users, err := fileStore.ListUsers()
	if err == nil {
		for _, user := range users {
			if err := sqlStore.CreateUser(user); err != nil {
				log.Printf("Warning: Failed to migrate user %s: %v", user.ID, err)
			} else {
				log.Printf("  ✓ Migrated user: %s", user.Username)
			}
		}
	}

	// Migrate groups
	log.Println("Migrating groups...")
	groups, err := fileStore.ListGroups()
	if err == nil {
		for _, group := range groups {
			if err := sqlStore.CreateGroup(group); err != nil {
				log.Printf("Warning: Failed to migrate group %s: %v", group.ID, err)
			} else {
				log.Printf("  ✓ Migrated group: %s", group.Name)
			}
		}
	}

	log.Println("\nMigration completed!")
	log.Println("Database saved to: ./tcpguard_migrated.db")
}
