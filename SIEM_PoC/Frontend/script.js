async function fetchServers() {
  try {
    const response = await fetch('http://localhost:8000/api/servers');
    if (!response.ok) throw new Error('Failed to fetch server data');

    const servers = await response.json();
    renderServers(servers);
  } catch (error) {
    console.error("Error fetching servers:", error);
    document.getElementById("dashboard").innerHTML = `<p style="color:red;">Failed to load server data.</p>`;
  }
}

function renderServers(serverList) {
  const dashboard = document.getElementById("dashboard");
  dashboard.innerHTML = "";

  serverList.forEach(server => {
    const card = document.createElement("div");
    card.className = "server-card";

    card.innerHTML = `
      <div class="server-header">
        <h2>${server.name}</h2>
        <div class="status-dot status-${server.status}"></div>
      </div>
      <div class="server-info">
        <p><strong>CPU Usage:</strong> ${server.cpu}%</p>
        <p><strong>Memory Usage:</strong>
