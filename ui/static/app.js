// Initialize elements
let form, targetInput, useCacheInput, shallowCloneInput, statusEl, resultSection;
let currentScanId = null;
let summaryEl, tableBody, dependencyTreeEl, reportsLinksEl;

function initElements() {
  form = document.getElementById("scan-form");
  targetInput = document.getElementById("target-input");
  useCacheInput = document.getElementById("use-cache");
  shallowCloneInput = document.getElementById("shallow-clone");
  statusEl = document.getElementById("status");
  resultSection = document.getElementById("result-section");
  summaryEl = document.getElementById("summary");
  tableBody = document.querySelector("#vulnerability-table tbody");
  dependencyTreeEl = document.getElementById("dependency-tree");
  reportsLinksEl = document.getElementById("reports-links");
}

function severityClass(severity) {
  const key = (severity || "none").toLowerCase();
  if (key === "critical") return "severity-critical";
  if (key === "high") return "severity-high";
  if (key === "medium") return "severity-medium";
  if (key === "low") return "severity-low";
  if (key === "negligible") return "severity-negligible";
  return "severity-none";
}

function renderSummary(report) {
  const summary = report.summary || {};
  summaryEl.innerHTML = 
    "<p><strong>Scan ID:</strong> " + report.scan_id + "</p>" +
    "<p><strong>Target:</strong> " + report.target + "</p>" +
    "<p><strong>Timestamp:</strong> " + new Date(report.timestamp).toLocaleString() + "</p>" +
    "<div class=\"summary-grid\">" +
    "<div><strong>Total Packages:</strong> " + (summary.total_packages || 0) + "</div>" +
    "<div><strong>Total Vulnerabilities:</strong> " + (summary.total_vulnerabilities || 0) + "</div>" +
    "<div><strong>Critical:</strong> " + (summary.critical || 0) + "</div>" +
    "<div><strong>High:</strong> " + (summary.high || 0) + "</div>" +
    "<div><strong>Medium:</strong> " + (summary.medium || 0) + "</div>" +
    "<div><strong>Low:</strong> " + (summary.low || 0) + "</div>" +
    "<div><strong>Negligible:</strong> " + (summary.negligible || 0) + "</div>" +
    "</div>";

  const jsonName = report.scan_id + ".json";
  const csvName = report.scan_id + ".csv";
  const dbMessage = report.database_message || "";
  reportsLinksEl.innerHTML = 
    "<p><a href=\"/reports/" + encodeURIComponent(jsonName) + "\" target=\"_blank\">Download JSON report</a> | " +
    "<a href=\"/reports/" + encodeURIComponent(csvName) + "\" target=\"_blank\">Download CSV report</a></p>" +
    (dbMessage ? "<div style=\"color: #2e7d32; margin-top: 15px; padding: 12px; background-color: #e8f5e9; border-radius: 4px; border-left: 4px solid #4caf50; font-weight: bold;\">✓ " + dbMessage + "</div>" : "");
}

/*
function renderTable(packages) {
  tableBody.innerHTML = "";
  if (!packages || packages.length === 0) {
    tableBody.innerHTML = "<tr><td colspan=\"6\">No packages found.</td></tr>";
    return;
  }

  // Show ALL packages, not just ones with vulnerabilities
  for (var i = 0; i < packages.length; i++) {
    var pkg = packages[i];
    var row = document.createElement("tr");
    var vulnId = pkg.vulnerability_id || "None";
    var severity = pkg.severity || "None";
    var fixedVer = pkg.fixed_version || "N/A";
    
    // Skip duplicate entries where the same package appears with "None" and real vulnerabilities
    if (vulnId === "None" || vulnId === "N/A") {
      var hasRealVuln = false;
      for (var j = 0; j < packages.length; j++) {
        if (packages[j].package === pkg.package && 
            packages[j].version === pkg.version &&
            packages[j].vulnerability_id && 
            packages[j].vulnerability_id !== "None" && 
            packages[j].vulnerability_id !== "N/A") {
          hasRealVuln = true;
          break;
        }
      }
      if (hasRealVuln) continue;
    }
    
    
    row.innerHTML = 
      "<td>" + pkg.package + "</td>" +
      "<td>" + pkg.version + "</td>" +
      "<td>" + pkg.type + "</td>" +
      "<td>" + vulnId + "</td>" +
      "<td><span class=\"severity-pill " + severityClass(severity) + "\">" + severity + "</span></td>" +
      "<td>" + fixedVer + "</td>";
    tableBody.appendChild(row);
  }
   */
  /* Added */ 
  function renderTable(packages) {

  tableBody.innerHTML = "";

  if (!packages || packages.length === 0) {
    tableBody.innerHTML = "<tr><td colspan='8'>No dependencies found.</td></tr>";
    return;
  }

  packages.forEach(pkg => {

    const row = document.createElement("tr");

    const severity = pkg.severity || "None";
    const latestVer = pkg.latest_version || pkg.version;
    const versionStatus = pkg.version_status || "unknown";

    let statusDisplay = "";
    if (versionStatus === "outdated") {
      statusDisplay = "<span style='color:red;font-weight:bold;'>Outdated</span>";
    } else if (versionStatus === "up_to_date") {
      statusDisplay = "<span style='color:green;font-weight:bold;'>Up-to-date</span>";
    } else {
      statusDisplay = "<span style='color:gray;'>Unknown</span>";
    }

    row.innerHTML =
      "<td>" + pkg.package + "</td>" +
      "<td>" + pkg.version + "</td>" +
      "<td>" + pkg.type + "</td>" +
      "<td>" + (pkg.vulnerability_id || "None") + "</td>" +
      "<td><span class='severity-pill " + severityClass(severity) + "'>" + severity + "</span></td>" +
      "<td>" + (pkg.fixed_version || "N/A") + "</td>" +
      "<td>" + latestVer + "</td>" +
      "<td>" + statusDisplay + "</td>";

    tableBody.appendChild(row);
  });
}

function downloadDependencyTree(tree, packages) {
  // Create package lookup
  var packageLookup = {};
  if (packages && packages.length > 0) {
    for (var i = 0; i < packages.length; i++) {
      var pkg = packages[i];
      if (pkg.package && pkg.version) {
        packageLookup[pkg.package] = pkg.package + "-" + pkg.version;
        packageLookup[pkg.package + "@" + pkg.version] = pkg.package + "-" + pkg.version;
      }
    }
  }
  
  // Format package names and SKIP hash IDs completely
  function formatNodeName(name) {
    if (packageLookup[name]) {
      return packageLookup[name];
    }
    // SKIP pure hash IDs
    if (/^[a-f0-9]+$/i.test(name) && name.length > 10) {
      return null;
    }
    if (name.indexOf("@") > 0) {
      var parts = name.split("@");
      if (parts.length === 2) {
        return parts[0] + "-" + parts[1];
      }
    }
    // Check for package-hash format
    if (name.indexOf("-") > 0) {
      var dashIndex = name.indexOf("-");
      var afterDash = name.substring(dashIndex + 1);
      if (/^[a-f0-9]+$/i.test(afterDash) && afterDash.length > 10) {
        return null; // Skip it
      }
    }
    return name;
  }
  
  // Filter tree to remove hash nodes and promote their children
  function filterTree(nodes) {
    var filtered = [];
    if (!nodes || nodes.length === 0) return filtered;
    
    for (var i = 0; i < nodes.length; i++) {
      var node = nodes[i];
      if (!node || !node.name) continue;
      
      var displayName = formatNodeName(node.name);
      
      // If hash ID, promote children instead of showing this node
      if (!displayName) {
        if (node.children && node.children.length > 0) {
          var promotedChildren = filterTree(node.children);
          for (var j = 0; j < promotedChildren.length; j++) {
            filtered.push(promotedChildren[j]);
          }
        }
        continue;
      }
      
      var newNode = { name: displayName };
      if (node.children && node.children.length > 0) {
        newNode.children = filterTree(node.children);
      }
      filtered.push(newNode);
    }
    return filtered;
  }
  
  var filteredTree = filterTree(tree);
  if (filteredTree.length === 0) {
    alert("No valid packages to display in tree (only hash IDs found)");
    return;
  }
  
  // Build tree structure with proper positioning
  var nodeWidth = 200;
  var nodeHeight = 50;
  var levelHeight = 120;
  var hSpacing = 30;
  
  function measureTree(nodes, depth) {
    var result = { width: 0, nodes: [] };
    if (!nodes || nodes.length === 0) return result;
    
    for (var i = 0; i < nodes.length; i++) {
      var node = nodes[i];
      var childMeasure = measureTree(node.children, depth + 1);
      var nodeInfo = {
        name: node.name,
        depth: depth,
        childWidth: Math.max(nodeWidth, childMeasure.width),
        children: childMeasure.nodes
      };
      result.nodes.push(nodeInfo);
      result.width += nodeInfo.childWidth + hSpacing;
    }
    result.width = Math.max(result.width - hSpacing, nodeWidth);
    return result;
  }
  
  var measured = measureTree(filteredTree, 0);
  var canvasWidth = Math.max(1200, measured.width + 100);
  var maxDepth = 0;
  
  function getMaxDepth(nodes) {
    var max = 0;
    if (!nodes || nodes.length === 0) return 0;
    for (var i = 0; i < nodes.length; i++) {
      max = Math.max(max, getMaxDepth(nodes[i].children) + 1);
    }
    return max;
  }
  maxDepth = getMaxDepth(measured.nodes);
  
  var canvasHeight = Math.max(600, maxDepth * levelHeight + 150);
  
  // Create canvas
  var canvas = document.createElement("canvas");
  canvas.width = canvasWidth;
  canvas.height = canvasHeight;
  var ctx = canvas.getContext("2d");
  
  // White background
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, canvasWidth, canvasHeight);
  
  // Draw title
  ctx.fillStyle = "#1a237e";
  ctx.font = "bold 24px Arial";
  ctx.textAlign = "center";
  ctx.fillText("Dependency Tree", canvasWidth / 2, 35);
  
  // Draw tree with proper branching
  function drawTree(nodes, x, y, depth, totalWidth) {
    if (!nodes || nodes.length === 0) return;
    
    var currentX = x;
    
    for (var i = 0; i < nodes.length; i++) {
      var node = nodes[i];
      var nodeX = currentX + node.childWidth / 2;
      var nodeY = y;
      
      // Draw node
      var level = "L" + depth;
      var color = getColorForLevel(depth);
      
      // Draw level badge
      ctx.fillStyle = color;
      ctx.fillRect(nodeX - 80, nodeY, 40, 35);
      ctx.fillStyle = "#ffffff";
      ctx.font = "bold 14px Arial";
      ctx.textAlign = "center";
      ctx.fillText(level, nodeX - 60, nodeY + 22);
      
      // Draw package box
      ctx.fillStyle = "#f8f9fa";
      ctx.fillRect(nodeX - 35, nodeY, 150, 35);
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.strokeRect(nodeX - 35, nodeY, 150, 35);
      
      // Draw text
      ctx.fillStyle = "#212121";
      ctx.font = "13px Arial";
      ctx.textAlign = "left";
      var truncated = node.name.length > 20 ? node.name.substring(0, 17) + "..." : node.name;
      ctx.fillText(truncated, nodeX - 30, nodeY + 22);
      
      // Draw children
      if (node.children && node.children.length > 0) {
        var childY = y + levelHeight;
        var childrenWidth = 0;
        for (var j = 0; j < node.children.length; j++) {
          childrenWidth += node.children[j].childWidth + hSpacing;
        }
        childrenWidth -= hSpacing;
        
        var childStartX = nodeX - childrenWidth / 2;
        var childCurrentX = childStartX;
        
        // Draw lines to children
        ctx.strokeStyle = "#90a4ae";
        ctx.lineWidth = 2;
        
        for (var j = 0; j < node.children.length; j++) {
          var child = node.children[j];
          var childCenterX = childCurrentX + child.childWidth / 2;
          
          // Draw line from parent to child
          ctx.beginPath();
          ctx.moveTo(nodeX, nodeY + 35);
          ctx.lineTo(nodeX, nodeY + 55);
          ctx.lineTo(childCenterX, nodeY + 55);
          ctx.lineTo(childCenterX, childY);
          ctx.stroke();
          
          childCurrentX += child.childWidth + hSpacing;
        }
        
        drawTree(node.children, childStartX, childY, depth + 1, childrenWidth);
      }
      
      currentX += node.childWidth + hSpacing;
    }
  }
  
  function getColorForLevel(depth) {
    var colors = [
      "#1976d2", // L0 - Blue
      "#388e3c", // L1 - Green
      "#f57c00", // L2 - Orange
      "#7b1fa2", // L3 - Purple
      "#c2185b", // L4 - Pink
      "#0097a7"  // L5+ - Cyan
    ];
    return colors[Math.min(depth, colors.length - 1)];
  }
  
  drawTree(measured.nodes, 50, 70, 0, measured.width);
  
  // Convert canvas to blob and download
  canvas.toBlob(function(blob) {
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = "dependency-tree.png";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });
}

function renderDependencyTree(tree, packages) {
  dependencyTreeEl.innerHTML = "";
  if (!tree || tree.length === 0) {
    dependencyTreeEl.innerHTML = "<div style=\"padding: 20px; text-align: center; color: #666;\"><p><strong>No dependency tree data available.</strong></p></div>";
    return;
  }

  // Build comprehensive package lookup
  var packageLookup = {};
  if (packages && packages.length > 0) {
    for (var i = 0; i < packages.length; i++) {
      var pkg = packages[i];
      if (pkg.package && pkg.version) {
        var formatted = pkg.package + "-" + pkg.version;
        // Add multiple lookup keys
        packageLookup[pkg.package] = formatted;
        packageLookup[pkg.package + "@" + pkg.version] = formatted;
        packageLookup[pkg.package + "-" + pkg.version] = formatted;
      }
    }
  }

  function formatPackageName(name) {
    if (!name) return null;
    
    // Skip pure hash IDs completely
    if (/^[a-f0-9]{8,}$/i.test(name)) {
      return null;
    }
    
    // Try direct lookup
    if (packageLookup[name]) {
      return packageLookup[name];
    }
    
    // Handle package@version format
    if (name.indexOf("@") > 0) {
      var atParts = name.split("@");
      if (atParts.length === 2) {
        var pkgName = atParts[0];
        var version = atParts[1];
        
        // Check if it's in our package list
        if (packageLookup[pkgName]) {
          return packageLookup[pkgName];
        }
        if (packageLookup[name]) {
          return packageLookup[name];
        }
        
        // Format it nicely
        if (version.charAt(0) === "v") {
          version = version.substring(1);
        }
        return pkgName + "-" + version;
      }
    }
    
    // Handle package-hash format - extract package name only
    if (name.indexOf("-") > 0) {
      var dashParts = name.split("-");
      var afterDash = dashParts[dashParts.length - 1];
      // If last part is a hash, remove it
      if (/^[a-f0-9]{8,}$/i.test(afterDash)) {
        var pkgWithoutHash = dashParts.slice(0, -1).join("-");
        if (packageLookup[pkgWithoutHash]) {
          return packageLookup[pkgWithoutHash];
        }
        return null; // Skip if we can't resolve it
      }
    }
    
    return name;
  }

  function createTreeList(nodes, depth) {
    if (!nodes || nodes.length === 0 || depth > 20) return null;
    depth = depth || 0;
    var list = document.createElement("ul");
    list.className = "tree-level tree-level-" + depth;
    
    for (var i = 0; i < nodes.length; i++) {
      var node = nodes[i];
      if (!node || !node.name) continue;
      
      var displayName = formatPackageName(node.name);
      
      // If hash ID, skip but process children at same level
      if (!displayName) {
        if (node.children && node.children.length > 0) {
          var childList = createTreeList(node.children, depth);
          if (childList && childList.childNodes) {
            for (var j = 0; j < childList.childNodes.length; j++) {
              list.appendChild(childList.childNodes[j].cloneNode(true));
            }
          }
        }
        continue;
      }
      
      var listItem = document.createElement("li");
      listItem.className = "tree-item level-" + depth;
      listItem.innerHTML = "<span class=\"level-badge\">L" + depth + "</span><span class=\"package-name\">" + displayName + "</span>";
      
      if (node.children && node.children.length > 0) {
        var childList = createTreeList(node.children, depth + 1);
        if (childList && childList.childNodes.length > 0) {
          listItem.appendChild(childList);
        }
      }
      list.appendChild(listItem);
    }
    return list.childNodes.length > 0 ? list : null;
  }

  var list = createTreeList(tree, 0);
  if (list) {
    var downloadBtn = document.createElement("button");
    downloadBtn.textContent = "📥 Download Dependency Tree";
    downloadBtn.className = "download-tree-btn";
    downloadBtn.style.marginBottom = "15px";
    downloadBtn.style.padding = "10px 20px";
    downloadBtn.style.backgroundColor = "#1976d2";
    downloadBtn.style.color = "white";
    downloadBtn.style.border = "none";
    downloadBtn.style.borderRadius = "4px";
    downloadBtn.style.cursor = "pointer";
    downloadBtn.style.fontSize = "14px";
    downloadBtn.style.fontWeight = "bold";
    downloadBtn.onmouseover = function() {
      this.style.backgroundColor = "#1565c0";
    };
    downloadBtn.onmouseout = function() {
      this.style.backgroundColor = "#1976d2";
    };
    downloadBtn.onclick = function() {
      downloadDependencyTree(tree, packages);
    };
    dependencyTreeEl.appendChild(downloadBtn);
    dependencyTreeEl.appendChild(list);
  } else {
    dependencyTreeEl.innerHTML = "<div style=\"padding: 20px; text-align: center; color: #666;\"><p><strong>Dependency tree is empty.</strong></p></div>";
  }
}

function setLoading(isLoading, message) {
  var button = document.getElementById("scan-button");
  if (button) button.disabled = isLoading;
  if (statusEl) {
    statusEl.innerHTML = message || "";
    statusEl.style.color = "#1f2937";
    statusEl.style.fontWeight = "600";
  }
  if (isLoading && resultSection) {
    resultSection.classList.add("hidden");
    resultSection.style.display = "none";
  }
}

function setupForm() {
  if (!form) {
    setTimeout(setupForm, 50);
    return;
  }

  form.addEventListener("submit", function(event) {
    event.preventDefault();

    // ✅ ADD HERE
    const loadingEl = document.getElementById("loading");
    if (loadingEl) loadingEl.style.display = "block";
    
    var target = targetInput.value.trim();
    if (!target) {
      setLoading(false, "Please enter a repository URL or local path.");
      return;
    }

    setLoading(true, "Preparing scan...");

    var payload = {
      target: target,
      useCache: useCacheInput.checked,
      shallowClone: shallowCloneInput.checked,
      skipVuln: false
    };

    var startTime = Date.now();
    var progressInterval = setInterval(function() {
      var elapsed = Math.floor((Date.now() - startTime) / 1000);
      var minutes = Math.floor(elapsed / 60);
      var seconds = elapsed % 60;
      var timeStr = minutes > 0 ? minutes + "m " + seconds + "s" : seconds + "s";
      setLoading(true, "Scanning in progress... Elapsed time: " + timeStr);
    }, 2000);

    fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    })
    .then(function(response) {
      if (!response.ok) {
        return response.json().then(function(err) {
          throw new Error(err.error || "Scan failed with status " + response.status);
        });
      }
      return response.json();
    })
    .then(function(data) {
      // ✅ LOADING STOP (SUCCESS)
      document.getElementById("loading").style.display = "none";
      clearInterval(progressInterval);
      
      if (data.error) {
        throw new Error(data.error);
      }
      //added
      currentScanId = data.scanId;
      //tillhere

      if (!data.report) {
        throw new Error("No report data received");
      }

      if (!summaryEl || !tableBody || !dependencyTreeEl || !reportsLinksEl) {
        initElements();
      }

      try {
        renderSummary(data.report);
      } catch (e) {
        console.error("Error rendering summary:", e);
      }
      
      try {
        renderTable(data.report.packages || []);
      } catch (e) {
        console.error("Error rendering table:", e);
      }
      
      try {
        renderDependencyTree(data.report.dependency_tree || [], data.report.packages || []);
      } catch (e) {
        console.error("Error rendering tree:", e);
      }

      //added
      // Load monitored version data immediately after scan
      fetch("/api/monitored")
      .then(res => res.json())
      .then(monitored => {
      updateVersionColumns(monitored);
      });
      //till here

      if (!resultSection) {
        resultSection = document.getElementById("result-section");
      }
      
      if (resultSection) {
        resultSection.classList.remove("hidden");
        resultSection.style.display = "block";
        resultSection.style.visibility = "visible";
        resultSection.style.opacity = "1";
        
        setTimeout(function() {
          resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
        }, 100);
      }

      var totalTime = Math.floor((Date.now() - startTime) / 1000);
      var totalMinutes = Math.floor(totalTime / 60);
      var totalSeconds = totalTime % 60;
      var totalTimeStr = totalMinutes > 0 ? totalMinutes + "m " + totalSeconds + "s" : totalSeconds + "s";
      
      var dbMessage = data.report.database_message || "";
      setLoading(false, "✔ Scan completed successfully in " + totalTimeStr + ". " + dbMessage);
    })
    .catch(function(error) {
      // ✅ ADD HERE
      document.getElementById("loading").style.display = "none";
      clearInterval(progressInterval);
      console.error("Scan error:", error);
      setLoading(false, "Error: " + (error.message || "Scan failed. Check browser console for details."));
    });
  });
}

//added
function updateVersionColumns(monitoredData) {

    if (!monitoredData || monitoredData.length === 0) return;

    const versionMap = {};

    monitoredData.forEach(row => {
        versionMap[row.package_name] = row;
    });

    const rows = document.querySelectorAll("#vulnerability-table tbody tr");

    rows.forEach(tr => {

        const pkgName = tr.children[0]?.innerText?.trim();

        if (versionMap[pkgName]) {

            // Column indexes:
            // 0 = Package
            // 1 = Version (current_version from DB)
            // 6 = Latest Version
            // 7 = Version Status

            tr.children[1].innerText =
                versionMap[pkgName].current_version;

            tr.children[6].innerText =
                versionMap[pkgName].latest_version;

            if (versionMap[pkgName].version_status === "outdated") {
                tr.children[7].innerHTML =
                    "<span style='color:red;font-weight:bold;'>Outdated</span>";
            } else if (versionMap[pkgName].version_status === "up_to_date") {
                tr.children[7].innerHTML =
                    "<span style='color:green;font-weight:bold;'>Up-to-date</span>";
            } else {
                tr.children[7].innerHTML =
                    "<span style='color:gray;'>Unknown</span>";
            }
        }
    });
}

// Auto refresh monitored table 
setInterval(() => {
    fetch('/api/monitored')
        .then(response => response.json())
        .then(data => {
            console.log("Auto updated data:", data);
            updateVersionColumns(data);
        })
        .catch(err => console.error("Auto update failed:", err));
}, 120000);

// added

// =========================
// FINAL CLEAN DOM LOAD
// =========================

document.addEventListener("DOMContentLoaded", () => {

  // INIT
  initElements();
  setupForm();

  // =========================
  // SEARCH + FILTER
  // =========================
  const searchInput = document.getElementById("searchInput");
  const outdatedToggle = document.getElementById("outdatedFilter");

  function filterTable() {
    const value = searchInput?.value.toLowerCase() || "";
    const onlyOutdated = outdatedToggle?.checked;

    const rows = document.querySelectorAll(".monitor-table tbody tr");

    rows.forEach(row => {
      const text = row.innerText.toLowerCase();
      const isOutdated = text.includes("outdated");

      row.style.display =
        (text.includes(value) && (!onlyOutdated || isOutdated))
          ? ""
          : "none";
    });
  }

  if (searchInput) searchInput.addEventListener("keyup", filterTable);
  if (outdatedToggle) outdatedToggle.addEventListener("change", filterTable);

  // =========================
  // CHARTS
  // =========================
  if (typeof Chart === "undefined") return;

  const trendData = window.trendData || [];
  const outdated = window.outdatedPackages || 0;
  const uptodate = window.uptodatePackages || 0;
  const severityLabels = window.severityLabels || [];
  const severityValues = window.severityValues || [];

  const labels = trendData.map(d => d[0]);
  const values = trendData.map(d => d[1]);

  const commonOptions = {
    plugins: {
      legend: {
        labels: { color: "#1e293b" }
      }
    },
    scales: {
      x: { ticks: { color: "#1e293b" } },
      y: { ticks: { color: "#1e293b" } }
    }
  };

  // HEALTH
  const healthCanvas = document.getElementById("healthChart");
  if (healthCanvas) {
    new Chart(healthCanvas, {
      type: "pie",
      data: {
        labels: ["Up-to-date", "Outdated"],
        datasets: [{
          data: [uptodate, outdated],
          backgroundColor: ["#22c55e", "#ef4444"]
        }]
      },
      options: commonOptions
    });
  }

  // TREND
  const trendCanvas = document.getElementById("trendChart");
  if (trendCanvas) {
    new Chart(trendCanvas, {
      type: "line",
      data: {
        labels: labels.length ? labels : ["Now"],
        datasets: [{
          label: "Outdated Packages",
          data: values.length ? values : [0],
          borderColor: "#3b82f6",
          backgroundColor: "rgba(59,130,246,0.2)",
          fill: true,
          tension: 0.4,
          pointRadius: 5
        }]
      },
      options: commonOptions
    });
  }

  // SEVERITY
  const severityCanvas = document.getElementById("severityChart");
  if (severityCanvas) {
    new Chart(severityCanvas, {
      type: "doughnut",
      data: {
        labels: severityLabels,
        datasets: [{
          data: severityValues,
          backgroundColor: ["#22c55e", "#f59e0b", "#ef4444"]
        }]
      },
      options: commonOptions
    });
  }

});