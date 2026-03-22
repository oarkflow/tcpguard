package tcpguard

import (
	"log"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
)

// InvestigationAPI provides HTTP handlers for the investigation service.
type InvestigationAPI struct {
	service     InvestigationService
	correlation CorrelationEngine
}

// NewInvestigationAPI creates a new InvestigationAPI.
func NewInvestigationAPI(service InvestigationService, correlation CorrelationEngine) *InvestigationAPI {
	return &InvestigationAPI{
		service:     service,
		correlation: correlation,
	}
}

// RegisterRoutes registers all investigation routes under the given prefix.
func (api *InvestigationAPI) RegisterRoutes(app *fiber.App, prefix string) {
	app.Get(prefix+"/timeline/:type/:value", api.QueryTimeline)
	app.Get(prefix+"/sessions/:id/story", api.GetSessionStory)
	app.Get(prefix+"/attacks", api.GetAttackPaths)
	app.Post(prefix+"/incidents", api.CreateIncident)
	app.Get(prefix+"/incidents", api.ListIncidents)
	app.Get(prefix+"/incidents/:id", api.GetIncident)
	app.Patch(prefix+"/incidents/:id", api.UpdateIncident)
	app.Get(prefix+"/incidents/:id/export", api.ExportEvidence)
	app.Get(prefix+"/entities/search", api.SearchEntities)
}

func (api *InvestigationAPI) QueryTimeline(c fiber.Ctx) error {
	key := CorrelationKey{
		Type:  c.Params("type"),
		Value: c.Params("value"),
	}

	var since, until time.Time
	if s := c.Query("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}
	if u := c.Query("until"); u != "" {
		if t, err := time.Parse(time.RFC3339, u); err == nil {
			until = t
		}
	}

	entries, err := api.service.QueryTimeline(c.Context(), key, since, until)
	if err != nil {
		log.Printf("investigation: QueryTimeline error: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
	}

	if limit := c.Query("limit"); limit != "" {
		if n, err := strconv.Atoi(limit); err == nil && n > 0 && n < len(entries) {
			entries = entries[:n]
		}
	}

	return c.JSON(entries)
}

func (api *InvestigationAPI) GetSessionStory(c fiber.Ctx) error {
	id := c.Params("id")
	story, err := api.correlation.GetSessionStory(c.Context(), id)
	if err != nil {
		log.Printf("investigation: GetSessionStory error for %s: %v", id, err)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "session not found"})
	}
	return c.JSON(story)
}

func (api *InvestigationAPI) GetAttackPaths(c fiber.Ctx) error {
	filter := AttackPathFilter{}

	if s := c.Query("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			filter.Since = t
		}
	}
	if sev := c.Query("severity"); sev != "" {
		filter.MinSeverity = sev
	}
	if l := c.Query("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			filter.Limit = n
		}
	}

	paths, err := api.correlation.GetAttackPaths(c.Context(), filter)
	if err != nil {
		log.Printf("investigation: GetAttackPaths error: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
	}
	return c.JSON(paths)
}

func (api *InvestigationAPI) CreateIncident(c fiber.Ctx) error {
	var incident Incident
	if err := c.Bind().JSON(&incident); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	result, err := api.service.CreateIncident(c.Context(), &incident)
	if err != nil {
		log.Printf("investigation: CreateIncident error: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
	}
	return c.Status(fiber.StatusCreated).JSON(result)
}

func (api *InvestigationAPI) ListIncidents(c fiber.Ctx) error {
	filter := IncidentFilter{}

	if s := c.Query("status"); s != "" {
		filter.Status = s
	}
	if sev := c.Query("severity"); sev != "" {
		filter.Severity = sev
	}
	if s := c.Query("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			filter.Since = t
		}
	}
	if l := c.Query("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			filter.Limit = n
		}
	}

	incidents, err := api.service.ListIncidents(c.Context(), filter)
	if err != nil {
		log.Printf("investigation: ListIncidents error: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
	}
	return c.JSON(incidents)
}

func (api *InvestigationAPI) GetIncident(c fiber.Ctx) error {
	id := c.Params("id")
	incident, err := api.service.GetIncident(c.Context(), id)
	if err != nil {
		log.Printf("investigation: GetIncident error for %s: %v", id, err)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "incident not found"})
	}
	return c.JSON(incident)
}

func (api *InvestigationAPI) UpdateIncident(c fiber.Ctx) error {
	id := c.Params("id")
	var update IncidentUpdate
	if err := c.Bind().JSON(&update); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	result, err := api.service.UpdateIncident(c.Context(), id, &update)
	if err != nil {
		log.Printf("investigation: UpdateIncident error for %s: %v", id, err)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "incident not found"})
	}
	return c.JSON(result)
}

func (api *InvestigationAPI) ExportEvidence(c fiber.Ctx) error {
	id := c.Params("id")
	export, err := api.service.ExportEvidence(c.Context(), id)
	if err != nil {
		log.Printf("investigation: ExportEvidence error for %s: %v", id, err)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "evidence not found"})
	}
	return c.JSON(export)
}

func (api *InvestigationAPI) SearchEntities(c fiber.Ctx) error {
	q := c.Query("q")
	if q == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "query parameter 'q' is required"})
	}

	results, err := api.service.SearchEntities(c.Context(), q)
	if err != nil {
		log.Printf("investigation: SearchEntities error: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
	}
	return c.JSON(results)
}
