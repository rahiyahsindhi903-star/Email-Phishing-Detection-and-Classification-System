import React, { useEffect, useRef, useState } from "react";
import Navbar from "../components/Navbar";

export default function QRScan() {
  const videoRef = useRef(null);
  const codeReaderRef = useRef(null);
  const [decodedText, setDecodedText] = useState("");
  const [scanning, setScanning] = useState(false);

  useEffect(() => {
    let active = true;
    setScanning(true);

    import("@zxing/browser").then(({ BrowserMultiFormatReader }) => {
      if (!active || !videoRef.current) return;
      const codeReader = new BrowserMultiFormatReader();
      codeReaderRef.current = codeReader;

      codeReader.decodeFromVideoDevice(
        null,
        videoRef.current,
        (result, err) => {
          if (result && active) {
            setDecodedText(result.getText());
            setScanning(false);
            codeReader.reset();
            codeReaderRef.current = null;
          }
        }
      );
    }).catch(console.error);

    return () => {
      active = false;
      if (codeReaderRef.current) {
        try {
          codeReaderRef.current.reset();
        } catch {}
      }
    };
  }, []);



  const scanBackend = async () => {

    const resp = await fetch("http://127.0.0.1:8000/scan/url", {

      method: "POST",

      headers: { "Content-Type": "application/json" },

      body: JSON.stringify({ url: decodedText }),

    });



    const data = await resp.json();

    alert(JSON.stringify(data, null, 2));

  };



  return (
    <div>
      <Navbar />
      <div style={{ padding: "20px" }}>

      <h1>Live QR Scanner</h1>



      <video

        ref={videoRef}

        style={{ width: "300px", border: "1px solid #000" }}

      />



      {decodedText && (

        <div style={{ marginTop: "20px" }}>

          <p>Decoded: {decodedText}</p>



          {decodedText.startsWith("http") && (

            <button onClick={scanBackend}>Scan URL</button>

          )}

        </div>

      )}

      </div>
    </div>
  );
}
