import React, { useEffect, useRef, useState } from "react";

import { BrowserMultiFormatReader } from "@zxing/browser";



export default function QRScan() {

  const videoRef = useRef(null);

  const [decodedText, setDecodedText] = useState("");

  const [scanning, setScanning] = useState(false);



  useEffect(() => {

    const codeReader = new BrowserMultiFormatReader();

    setScanning(true);



    codeReader.decodeFromVideoDevice(

      null,

      videoRef.current,

      (result, err) => {

        if (result) {

          setDecodedText(result.getText());

          setScanning(false);

          codeReader.reset();

        }

      }

    );



    return () => {

      try {

        codeReader.reset();

      } catch {}

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

  );

}
