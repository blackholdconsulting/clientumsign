# Clientum Signer

API mínima para firmar XML Facturae en **XAdES** (EPES si se pasa política).

## Endpoints

- `GET /health` → `"OK"`
- `POST /xades-epes` → firma XAdES. **Body JSON**:

```json
{
  "xml": "<Facturae xmlns=\"http://www.facturae.es/Facturae/2009/v3.2.2/Facturae\">...</Facturae>",
  "p12": "BASE64_DEL_P12",
  "password": "claveP12",
  "policyId": "urn:facturae:policies:facturae-3-1",
  "policyUrl": "https://www.facturae.gob.es/Politica_de_firma/Politica_de_firma_v3_1.pdf",
  "policyHashBase64": "BASE64_DEL_HASH",
  "policyDigest": "SHA256"
}
