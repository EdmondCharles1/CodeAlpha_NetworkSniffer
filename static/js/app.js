let currentFilter = "ALL";

// Appeler l'API toutes les secondes
setInterval(fetchData, 1000);

async function fetchData() {
  // 1. Récupérer les stats
  const statsRes = await fetch("/api/stats");
  const stats = await statsRes.json();

  document.getElementById("statTotal").textContent = stats.total;
  document.getElementById("statTcp").textContent = stats.tcp;
  document.getElementById("statUdp").textContent = stats.udp;
  document.getElementById("statIcmp").textContent = stats.icmp;
  document.getElementById("statOther").textContent = stats.other;

  // 2. Mettre à jour les barres
  const total = stats.total || 1;
  updateBar("Tcp", stats.tcp, total);
  updateBar("Udp", stats.udp, total);
  updateBar("Icmp", stats.icmp, total);
  updateBar("Other", stats.other, total);

  // 3. Récupérer les paquets
  const packetsRes = await fetch("/api/packets?protocol=" + currentFilter);
  const packets = await packetsRes.json();

  // 4. Mettre à jour le tableau
  const tbody = document.getElementById("packetBody");
  tbody.innerHTML = "";
  packets.forEach((p) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
            <td>${p.src_ip}</td>
            <td>${p.dest_ip}</td>
            <td><span class="tag tag-${p.protocol}">${p.protocol}</span></td>
            <td>${p.src_port || "—"}</td>
            <td>${p.dest_port || "—"}</td>
            <td>${p.ttl}</td>
        `;
    tbody.appendChild(tr);
  });

  // 5. Top IPs
  const ipCount = {};
  packets.forEach((p) => {
    ipCount[p.src_ip] = (ipCount[p.src_ip] || 0) + 1;
  });
  const sorted = Object.entries(ipCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);
  const topDiv = document.getElementById("topIps");
  topDiv.innerHTML = sorted
    .map(
      ([ip, count]) =>
        `<div class="ip-row"><span>${ip}</span><span class="ip-count">${count}</span></div>`,
    )
    .join("");
}

function updateBar(name, count, total) {
  const pct = ((count / total) * 100).toFixed(1);
  document.getElementById("bar" + name).style.width = pct + "%";
  document.getElementById("count" + name).textContent = count;
}

function setFilter(btn, proto) {
  document
    .querySelectorAll(".filter-btn")
    .forEach((b) => b.classList.remove("active"));
  btn.classList.add("active");
  currentFilter = proto;
}

function exportData(fmt) {
  window.open("/api/export/" + fmt + "?protocol=" + currentFilter, "_blank");
}
