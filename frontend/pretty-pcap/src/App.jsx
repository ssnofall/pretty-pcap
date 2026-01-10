import { useState, useMemo } from "react";
import "./App.css";

function App() {
  const [packets, setPackets] = useState([]);
  const [statistics, setStatistics] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [filePath, setFilePath] = useState("");
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [filterText, setFilterText] = useState("");
  const [filterProtocol, setFilterProtocol] = useState("all");
  const [sortColumn, setSortColumn] = useState("no");
  const [sortDirection, setSortDirection] = useState("asc");
  const [showStats, setShowStats] = useState(false);

  // ------------------------
  // File picker
  const selectFile = async () => {
    const path = await window.electronAPI.selectFile();
    if (path) {
      setFilePath(path);
      setPackets([]);
      setStatistics(null);
      setSelectedPacket(null);
      setError(null);
      setFilterText("");
      setFilterProtocol("all");
    }
  };

  // ------------------------
  // Fetch parsed PCAP from Flask
  const parsePcap = async () => {
    if (!filePath) return;

    setLoading(true);
    setError(null);

    try {
      const response = await fetch("http://127.0.0.1:5050/parse", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ file_path: filePath }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `HTTP error: ${response.status}`);
      }

      const data = await response.json();
      setPackets(data.packets || []);
      setStatistics(data.statistics || null);
      if (data.packets && data.packets.length > 0) {
        setSelectedPacket(data.packets[0]);
      }
    } catch (err) {
      console.error(err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // ------------------------
  // Filtering and sorting
  const filteredAndSortedPackets = useMemo(() => {
    let filtered = [...packets];

    // Filter by protocol
    if (filterProtocol !== "all") {
      filtered = filtered.filter((p) => p.protocol === filterProtocol);
    }

    // Filter by text search
    if (filterText) {
      const searchLower = filterText.toLowerCase();
      filtered = filtered.filter((p) => {
        return (
          (p.src_ip && p.src_ip.toLowerCase().includes(searchLower)) ||
          (p.dst_ip && p.dst_ip.toLowerCase().includes(searchLower)) ||
          (p.protocol && p.protocol.toLowerCase().includes(searchLower)) ||
          (p.info && p.info.toLowerCase().includes(searchLower)) ||
          (p.src_port && p.src_port.toString().includes(searchLower)) ||
          (p.dst_port && p.dst_port.toString().includes(searchLower))
        );
      });
    }

    // Sort
    filtered.sort((a, b) => {
      let aVal = a[sortColumn];
      let bVal = b[sortColumn];

      if (typeof aVal === "string") {
        aVal = aVal.toLowerCase();
        bVal = bVal.toLowerCase();
      }

      if (sortDirection === "asc") {
        return aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
      } else {
        return aVal < bVal ? 1 : aVal > bVal ? -1 : 0;
      }
    });

    return filtered;
  }, [packets, filterText, filterProtocol, sortColumn, sortDirection]);

  // ------------------------
  // Protocol colors
  const getProtocolColor = (protocol) => {
    const colors = {
      TCP: "#3b82f6",
      UDP: "#10b981",
      ARP: "#f59e0b",
      ICMP: "#ef4444",
      DNS: "#8b5cf6",
      HTTP: "#ec4899",
      IP: "#6b7280",
      L2_UNKNOWN: "#9ca3af",
    };
    return colors[protocol] || "#6b7280";
  };

  // ------------------------
  // Format time
  const formatTime = (time, relative = true) => {
    if (relative) {
      if (time < 1) {
        return `${(time * 1000).toFixed(3)} ms`;
      }
      return `${time.toFixed(6)} s`;
    }
    return new Date(time * 1000).toLocaleString();
  };

  // ------------------------
  // Handle column sort
  const handleSort = (column) => {
    if (sortColumn === column) {
      setSortDirection(sortDirection === "asc" ? "desc" : "asc");
    } else {
      setSortColumn(column);
      setSortDirection("asc");
    }
  };

  // ------------------------
  // Get unique protocols
  const uniqueProtocols = useMemo(() => {
    const protocols = new Set(packets.map((p) => p.protocol).filter(Boolean));
    return Array.from(protocols).sort();
  }, [packets]);

  // ------------------------
  // Render packet details
  const renderPacketDetails = (packet) => {
    if (!packet) return null;

    const sections = [];

    // Frame information
    sections.push({
      title: "Frame",
      data: {
        "Packet Number": packet.no,
        "Time": formatTime(packet.time, false),
        "Time Relative": formatTime(packet.time_relative, true),
        "Time Delta": formatTime(packet.time_delta, true),
        "Length": `${packet.length} bytes`,
        "Captured Length": `${packet.length_caplen || packet.length} bytes`,
      },
    });

    // Ethernet
    if (packet.eth_src || packet.eth_dst) {
      sections.push({
        title: "Ethernet II",
        data: {
          "Destination": packet.eth_dst || "-",
          "Source": packet.eth_src || "-",
          "Type": packet.eth_type || "-",
        },
      });
    }

    // IP
    if (packet.src_ip && packet.ip_version) {
      sections.push({
        title: "Internet Protocol Version 4",
        data: {
          "Version": packet.ip_version,
          "Source": packet.src_ip,
          "Destination": packet.dst_ip,
          "TTL": packet.ip_ttl || "-",
          "TOS": packet.ip_tos || "-",
          "ID": packet.ip_id || "-",
          "Flags": packet.ip_flags || "-",
          "Fragment": packet.ip_frag || "-",
        },
      });
    }

    // TCP
    if (packet.protocol === "TCP") {
      sections.push({
        title: "Transmission Control Protocol",
        data: {
          "Source Port": packet.src_port || "-",
          "Destination Port": packet.dst_port || "-",
          "Sequence Number": packet.tcp_seq || "-",
          "Acknowledgment Number": packet.tcp_ack || "-",
          "Flags": packet.tcp_flags_str || "-",
          "Window Size": packet.tcp_window || "-",
          "Urgent Pointer": packet.tcp_urgent || "-",
          "Options": packet.tcp_options || "None",
        },
      });
    }

    // UDP
    if (packet.protocol === "UDP") {
      sections.push({
        title: "User Datagram Protocol",
        data: {
          "Source Port": packet.src_port || "-",
          "Destination Port": packet.dst_port || "-",
          "Length": packet.udp_length || "-",
          "Checksum": packet.udp_checksum || "-",
        },
      });
    }

    // ICMP
    if (packet.protocol === "ICMP") {
      sections.push({
        title: "Internet Control Message Protocol",
        data: {
          "Type": packet.icmp_type || "-",
          "Code": packet.icmp_code || "-",
          "ID": packet.icmp_id || "-",
          "Sequence": packet.icmp_seq || "-",
        },
      });
    }

    // DNS
    if (packet.dns_qname) {
      sections.push({
        title: "Domain Name System",
        data: {
          "Query Name": packet.dns_qname || "-",
          "Query Type": packet.dns_qtype || "-",
          "Response": packet.dns_response ? "Yes" : "No",
          "Response Code": packet.dns_rcode || "-",
          "Answer Count": packet.dns_ancount || "-",
          "Authority Count": packet.dns_nscount || "-",
          "Additional Count": packet.dns_arcount || "-",
        },
      });
    }

    // HTTP
    if (packet.http_method || packet.http_status) {
      sections.push({
        title: "Hypertext Transfer Protocol",
        data: {
          "Method": packet.http_method || "-",
          "Path": packet.http_path || "-",
          "Version": packet.http_version || "-",
          "Status": packet.http_status || "-",
          "Reason": packet.http_reason || "-",
          "Headers": packet.http_headers
            ? JSON.stringify(packet.http_headers, null, 2)
            : "-",
        },
      });
    }

    // Payload
    if (packet.payload_len > 0) {
      sections.push({
        title: "Payload",
        data: {
          "Length": `${packet.payload_len} bytes`,
          "Hex": packet.payload_hex || "-",
          "ASCII": packet.payload_ascii || "-",
        },
      });
    }

    return (
      <div className="packet-details">
        {sections.map((section, idx) => (
          <div key={idx} className="detail-section">
            <div className="detail-section-title">{section.title}</div>
            <div className="detail-section-content">
              {Object.entries(section.data).map(([key, value]) => (
                <div key={key} className="detail-row">
                  <span className="detail-key">{key}:</span>
                  <span className="detail-value">{String(value)}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    );
  };

  // ------------------------
  // Render hex dump
  const renderHexDump = (packet) => {
    if (!packet || !packet.raw_hex) return null;

    const hexBytes = packet.raw_hex.split(" ");
    const asciiChars = packet.raw_ascii || "";

    const rows = [];
    const bytesPerRow = 16;

    for (let i = 0; i < hexBytes.length; i += bytesPerRow) {
      const rowHex = hexBytes.slice(i, i + bytesPerRow);
      const rowAscii = asciiChars.slice(i, i + bytesPerRow);
      const offset = i.toString(16).padStart(8, "0").toUpperCase();

      rows.push(
        <div key={i} className="hex-row">
          <span className="hex-offset">{offset}</span>
          <span className="hex-bytes">
            {rowHex.map((byte, idx) => (
              <span key={idx} className="hex-byte">
                {byte}
              </span>
            ))}
            {rowHex.length < bytesPerRow &&
              Array(bytesPerRow - rowHex.length)
                .fill("")
                .map((_, idx) => (
                  <span key={idx} className="hex-byte empty">
                    {"  "}
                  </span>
                ))}
          </span>
          <span className="hex-ascii">{rowAscii}</span>
        </div>
      );
    }

    return <div className="hex-dump">{rows}</div>;
  };

  return (
    <div className="app">
      {/* Header */}
      <header className="app-header">
        <h1 className="app-title">
          Pretty PCAP Viewer
        </h1>
        <div className="header-controls">
          <button
            className="btn btn-primary"
            onClick={selectFile}
            disabled={loading}
          >
            Select PCAP File
          </button>
          <button
            className="btn btn-secondary"
            onClick={parsePcap}
            disabled={loading || !filePath}
          >
            {loading ? "Parsing..." : "Parse PCAP"}
          </button>
          {statistics && (
            <button
              className={`btn btn-tertiary ${showStats ? "active" : ""}`}
              onClick={() => setShowStats(!showStats)}
            >
              Statistics
            </button>
          )}
        </div>
      </header>

      {/* File path display */}
      {filePath && (
        <div className="file-path-display">
          <span className="file-path">{filePath}</span>
        </div>
      )}

      {/* Error display */}
      {error && (
        <div className="error-banner">
          <span>{error}</span>
        </div>
      )}

      {/* Statistics Panel */}
      {showStats && statistics && (
        <div className="stats-panel">
          <h2>Capture Statistics</h2>
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-label">Total Packets</div>
              <div className="stat-value">{statistics.total_packets}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Total Bytes</div>
              <div className="stat-value">
                {(statistics.total_bytes / 1024).toFixed(2)} KB
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Duration</div>
              <div className="stat-value">
                {formatTime(statistics.duration, true)}
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Packets/sec</div>
              <div className="stat-value">
                {statistics.packets_per_second.toFixed(2)}
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Avg Packet Size</div>
              <div className="stat-value">
                {statistics.avg_packet_size.toFixed(2)} bytes
              </div>
            </div>
          </div>
          <div className="protocol-stats">
            <h3>Protocol Distribution</h3>
            <div className="protocol-list">
              {Object.entries(statistics.protocol_counts || {})
                .sort((a, b) => b[1] - a[1])
                .map(([protocol, count]) => (
                  <div
                    key={protocol}
                    className="protocol-stat-item"
                    style={{
                      borderLeftColor: getProtocolColor(protocol),
                    }}
                  >
                    <span className="protocol-name">{protocol}</span>
                    <span className="protocol-count">{count}</span>
                    <span className="protocol-percent">
                      {((count / statistics.total_packets) * 100).toFixed(1)}%
                    </span>
                  </div>
                ))}
            </div>
          </div>
        </div>
      )}

      {/* Main content */}
      {packets.length > 0 && (
        <div className="main-content">
          {/* Left panel - Packet list */}
          <div className="packet-list-panel">
            <div className="panel-header">
              <h2>Packet List ({filteredAndSortedPackets.length})</h2>
              <div className="filters">
                <input
                  type="text"
                  className="filter-input"
                  placeholder="Search packets..."
                  value={filterText}
                  onChange={(e) => setFilterText(e.target.value)}
                />
                <select
                  className="filter-select"
                  value={filterProtocol}
                  onChange={(e) => setFilterProtocol(e.target.value)}
                >
                  <option value="all">All Protocols</option>
                  {uniqueProtocols.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div className="packet-table-container">
              <table className="packet-table">
                <thead>
                  <tr>
                    <th onClick={() => handleSort("no")} className="sortable">
                      No {sortColumn === "no" && (sortDirection === "asc" ? "↑" : "↓")}
                    </th>
                    <th onClick={() => handleSort("time_relative")} className="sortable">
                      Time {sortColumn === "time_relative" && (sortDirection === "asc" ? "↑" : "↓")}
                    </th>
                    <th onClick={() => handleSort("src_ip")} className="sortable">
                      Source {sortColumn === "src_ip" && (sortDirection === "asc" ? "↑" : "↓")}
                    </th>
                    <th onClick={() => handleSort("dst_ip")} className="sortable">
                      Destination {sortColumn === "dst_ip" && (sortDirection === "asc" ? "↑" : "↓")}
                    </th>
                    <th onClick={() => handleSort("protocol")} className="sortable">
                      Protocol {sortColumn === "protocol" && (sortDirection === "asc" ? "↑" : "↓")}
                    </th>
                    <th onClick={() => handleSort("length")} className="sortable">
                      Length {sortColumn === "length" && (sortDirection === "asc" ? "↑" : "↓")}
                    </th>
                    <th>Info</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredAndSortedPackets.map((pkt) => {
                    const isSelected = selectedPacket?.no === pkt.no;
                    const protocolColor = getProtocolColor(pkt.protocol);

                    return (
                      <tr
                        key={pkt.no}
                        className={isSelected ? "selected" : ""}
                        onClick={() => setSelectedPacket(pkt)}
                        style={{
                          borderLeft: `3px solid ${protocolColor}`,
                        }}
                      >
                        <td>{pkt.no}</td>
                        <td>{formatTime(pkt.time_relative, true)}</td>
                        <td>
                          {pkt.src_ip || "-"}
                          {pkt.src_port && `:${pkt.src_port}`}
                        </td>
                        <td>
                          {pkt.dst_ip || "-"}
                          {pkt.dst_port && `:${pkt.dst_port}`}
                        </td>
                        <td>
                          <span
                            className="protocol-badge"
                            style={{ backgroundColor: protocolColor }}
                          >
                            {pkt.protocol}
                          </span>
                        </td>
                        <td>{pkt.length}</td>
                        <td className="info-cell">{pkt.info || "-"}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Right panels - Details and Hex */}
          <div className="detail-panels">
            {/* Packet Details */}
            <div className="detail-panel">
              <div className="panel-header">
                <h2>Packet Details</h2>
              </div>
              <div className="detail-panel-content">
                {selectedPacket ? (
                  renderPacketDetails(selectedPacket)
                ) : (
                  <div className="no-selection">Select a packet to view details</div>
                )}
              </div>
            </div>

            {/* Hex Dump */}
            <div className="hex-panel">
              <div className="panel-header">
                <h2>Hex Dump</h2>
              </div>
              <div className="hex-panel-content">
                {selectedPacket ? (
                  renderHexDump(selectedPacket)
                ) : (
                  <div className="no-selection">Select a packet to view hex dump</div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Empty state */}
      {!loading && packets.length === 0 && !error && (
        <div className="empty-state">
          <div className="empty-icon">📦</div>
          <h2>No packets loaded</h2>
          <p>Select a PCAP file and click "Parse PCAP" to begin</p>
        </div>
      )}
    </div>
  );
}

export default App;
