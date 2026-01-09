import { useState } from "react";

function App() {
  const [packets, setPackets] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [filePath, setFilePath] = useState("");

  const selectFile = async () => {
    const path = await window.electronAPI.selectFile();
    if (path) {
      setFilePath(path);
      setPackets([]); // clear previous results
      setError(null);
    }
  };

  const parsePcap = async () => {
    if (!filePath) return;

    setLoading(true);
    setError(null);

    try {
      const response = await fetch("http://127.0.0.1:5000/parse", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ file_path: filePath }),
      });

      if (!response.ok) throw new Error(`HTTP error: ${response.status}`);

      const data = await response.json();
      setPackets(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: "20px" }}>
      <h1>Pretty PCAP Viewer</h1>
      <button onClick={selectFile}>Select PCAP File</button>
      {filePath && <p>Selected file: {filePath}</p>}

      <button onClick={parsePcap} disabled={loading || !filePath}>
        {loading ? "Loading..." : "Parse PCAP"}
      </button>

      {error && <p style={{ color: "red" }}>{error}</p>}

      {packets.length > 0 && (
        <table border="1" cellPadding="5" style={{ marginTop: "20px" }}>
          <thead>
            <tr>
              <th>Time</th>
              <th>Src IP</th>
              <th>Dst IP</th>
              <th>Protocol</th>
              <th>Length</th>
            </tr>
          </thead>
          <tbody>
            {packets.map((pkt, index) => (
              <tr key={index}>
                <td>{pkt.time}</td>
                <td>{pkt.src_ip || "-"}</td>
                <td>{pkt.dst_ip || "-"}</td>
                <td>{pkt.protocol}</td>
                <td>{pkt.length}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default App;
