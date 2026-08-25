package app

import (
	"strings"

	"github.com/ZentWorks/ZentContainer/internal/dockerx"
)

// enrichNetworkContainerMembership fills the network-list response from the
// container list. Docker's GET /networks response does not consistently expose
// Containers, while container summaries reliably expose their network
// attachments. NetworkInspect remains the authoritative detailed view.
func enrichNetworkContainerMembership(networks []dockerx.Network, containers []dockerx.ContainerSummary) []dockerx.Network {
	byName := make(map[string]int, len(networks))
	byID := make(map[string]int, len(networks))
	for i := range networks {
		byName[networks[i].Name] = i
		byID[networks[i].ID] = i
		if networks[i].Containers == nil {
			networks[i].Containers = map[string]dockerx.NetworkContainer{}
		}
	}
	for _, c := range containers {
		name := strings.TrimPrefix(firstContainerName(c.Names), "/")
		for networkName, ep := range c.NetworkSettings.Networks {
			i, ok := byName[networkName]
			if !ok && ep.NetworkID != "" {
				i, ok = byID[ep.NetworkID]
			}
			if !ok {
				continue
			}
			networks[i].Containers[c.ID] = dockerx.NetworkContainer{
				Name:        name,
				IPv4Address: ep.IPAddress,
			}
		}
	}
	return networks
}

func firstContainerName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return names[0]
}
