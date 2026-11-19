import React, { useState } from "react";



export default function QRUpload() {

  const [loading, setLoading] = useState(false);

  const [result, setResult] = useState(null);



  const handleFile = async (e) => {

    const file = e.target.files[0];

    if (!file) return;



    setLoading(true);

    setResult(null);



    const formData = new FormData();

    formData.append("file", file);



    try {

      const resp = await fetch("http://127.0.0.1:8000/scan/qr", {

        method: "POST",

        body: formData,

      });



      const text = await resp.text(); // get raw response

      let json;



      try {

        json = JSON.parse(text);

      } catch (err) {

        json = { error: "Invalid JSON returned from backend", raw: text };

      }



      setResult(json);



    } catch (error) {

      setResult({ error: error.toString() });

    } finally {

      setLoading(false);

    }

  };



  return (

    <div style={{ padding: "20px" }}>

      <h1>QR Image Upload Scanner</h1>



      <input type="file" accept="image/*" onChange={handleFile} />



      {loading && <p>Scanning...</p>}



      {result && (

        <pre style={{ marginTop: "20px", background: "#eee", padding: "15px" }}>

          {JSON.stringify(result, null, 2)}

        </pre>

      )}

    </div>

  );

}
