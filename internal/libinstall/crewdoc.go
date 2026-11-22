package libinstall

import (
	"fmt"

	"github.com/vulnetix/belai/internal/agentprofile"
	"github.com/vulnetix/belai/internal/sanitize"
)

// SaveCrew writes a crew whose document the caller has already parsed
// strictly (a Keleustes library_install, whose member profiles travel as
// their own items in the same dispatch, profiles first). It holds the crew to
// what Crew does after its members: CrewConflict (no replace without
// overwrite, no id taken from another name), then agentprofile.SaveCrew,
// which refuses a member that is not a worker profile on this host, so
// nothing is written for a crew whose members are missing.
func (i Installer) SaveCrew(c agentprofile.Crew, overwrite bool) (report, why string) {
	c.Builtin = false
	if !agentprofile.ValidID(c.ID) {
		return "", "the crew has no valid id"
	}
	if why := CrewConflict(c, overwrite); why != "" {
		return "", why
	}
	if _, err := agentprofile.SaveCrew(c); err != nil {
		return "", "the crew is not valid here: " + reason(err.Error())
	}
	if js, err := c.CanonicalJSON(); err == nil && i.Saved != nil {
		i.Saved("crew", c.ID, js)
	}
	return fmt.Sprintf("installed crew %s with %d member%s", sanitize.Line(c.Name, 64), len(c.Members), plural(len(c.Members), "", "s")), ""
}
