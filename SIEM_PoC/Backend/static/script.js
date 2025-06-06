async function fetchServers() {
  try {
    const response = await fetch('/api/servers');
    if (!response.ok) throw new Error('Failed to fetch server data');

    const servers = await response.json();
    renderServers(servers);
  } catch (error) {
    console.error("Error fetching servers:", error);
    document.getElementById("dashboard").innerHTML = `<p style="color:red;">Failed to load server data.</p>`;
  }
}

function getUsageColor(value) {
  if (value < 50) return "green";
  if (value < 80) return "orange";
  return "red";
}

function renderServers(serverList) {
  const dashboard = document.getElementById("dashboard");
  dashboard.innerHTML = "";

  serverList.forEach(server => {
    const card = document.createElement("div");
    card.className = "server-card";

    const cpuColor = getUsageColor(server.cpu);
    const memColor = getUsageColor(server.memory);

    let errorHTML = "";
    if (server.error) {
      errorHTML = `<p class="error-text">⚠️ ${server.error}</p>`;
    }

    card.innerHTML = `
      <div class="server-header">
        <h2>${server.name}</h2>
        <div class="status-dot status-${server.status}"></div>
      </div>
      <div class="server-info">
        <p><strong>CPU Usage:</strong> <span style="color:${cpuColor}">${server.cpu}%</span></p>
        <p><strong>Memory Usage:</strong> <span style="color:${memColor}">${server.memory}%</span></p>
        <p><strong>Uptime:</strong> ${server.uptime || 'Unknown'}</p>
        ${errorHTML}
      </div>
      <div class="server-actions">
        <button onclick="refreshServer('${server.name}', this)">🔄 Refresh</button>
      </div>
    `;

    dashboard.appendChild(card);
  });
}

// Initial fetch on load
window.onload = fetchServers;

// Refresh every 60 seconds
setInterval(fetchServers, 60000);

// Manual refresh
document.getElementById("refreshButton").addEventListener("click", fetchServers);
