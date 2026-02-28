# FOREX RATES API

## MobiRates - MobiCard Global Currency Exchange (Java)

Access real-time foreign exchange rates with MobiCard's Forex Rates API. Get accurate currency conversion data for 160+ currencies worldwide, updated in real-time for financial applications, e-commerce platforms, and payment systems.

Retrieve comprehensive forex rate data including base currency rates, historical comparisons, and real-time exchange values. Perfect for payment processing, financial reporting, multi-currency pricing, and international transaction calculations.

### Forex Rates API Overview

Retrieve real-time foreign exchange rates for global currencies. The API returns exchange rate data for a specified base currency against all supported currencies or a single target currency.

###Forex Rates Implementation

Generate a signed JWT token with embedded request.

Send currency query parameters to receive real-time forex rate information. Specify a target currency or retrieve all available rates.

### Success Response Format (All Currencies)

The Forex Rates API returns comprehensive currency exchange rate information upon successful request.
```json
{
  "status": "SUCCESS",
  "status_code": "200",
  "status_message": "SUCCESS",
  "mobicard_txn_reference": "694329793",
  "base_currency": "USD",
  "timestamp": "2026-01-29 16:31:01",
  "forex_rates": {
    "USDAED": 3.6725,
    "USDAFN": 65.786799,
    "USDALL": 80.757863,
    "USDAMD": 379.022763,
    "USDANG": 1.79,
    "USDAOA": 919.969957,
    "USDARS": 1452.25,
    "USDAUD": 1.426189,
    "USDAWG": 1.79,
    "USDAZN": 1.701021,
    "USDBAM": 1.634147,
    "USDBBD": 2,
    "USDBDT": 122.172587,
    "USDBGN": 1.586662,
    "USDBHD": 0.376,
    "USDBIF": 2965.410723,
    "USDBMD": 1,
    "USDBND": 1.262208,
    "USDBOB": 6.921391,
    "USDBRL": 5.185441,
    "USDBSD": 1,
    "USDBTN": 91.98174,
    "USDBWP": 13.341705,
    "USDBYN": 2.842833,
    "USDBZD": 2,
    "USDCAD": 1.355899,
    "USDCDF": 2273.753865,
    "USDCHF": 0.767528,
    "USDCLF": 0.021751,
    "USDCLP": 859.720171,
    "USDCNH": 6.945914,
    "USDCNY": 6.956121,
    "USDCOP": 3658.806441,
    "USDCRC": 496.272755,
    "USDCUP": 24,
    "USDCVE": 92.12927,
    "USDCZK": 20.316824,
    "USDDJF": 177.721,
    "USDDKK": 6.233971,
    "USDDOP": 62.768691,
    "USDDZD": 129.194681,
    "USDEGP": 46.948579,
    "USDERN": 15,
    "USDETB": 154.573997,
    "USDEUR": 0.835547,
    "USDFJD": 2.200791,
    "USDFKP": 0.724654,
    "USDFOK": 6.235422,
    "USDGBP": 0.724665,
    "USDGEL": 2.693268,
    "USDGGP": 0.724654,
    "USDGHS": 10.945947,
    "USDGIP": 0.724654,
    "USDGMD": 74.161993,
    "USDGNF": 8758.161855,
    "USDGTQ": 7.675976,
    "USDGYD": 209.303852,
    "USDHKD": 7.801394,
    "USDHNL": 26.377972,
    "USDHRK": 6.29527,
    "USDHTG": 130.927308,
    "USDHUF": 318.110635,
    "USDIDR": 16739.365495,
    "USDILS": 3.093639,
    "USDIMP": 0.724654,
    "USDINR": 92.007801,
    "USDIQD": 1309.869488,
    "USDIRR": 1076714.568598,
    "USDISK": 121.115831,
    "USDJEP": 0.724654,
    "USDJMD": 156.829412,
    "USDJOD": 0.709,
    "USDJPY": 153.126485,
    "USDKES": 129.036529,
    "USDKGS": 87.469459,
    "USDKHR": 4019.241365,
    "USDKID": 1.426174,
    "USDKMF": 411.051827,
    "USDKRW": 1431.350768,
    "USDKWD": 0.306041,
    "USDKYD": 0.833333,
    "USDKZT": 504.11722,
    "USDLAK": 21523.427823,
    "USDLBP": 89500,
    "USDLKR": 309.753929,
    "USDLRD": 184.387941,
    "USDLSL": 15.829801,
    "USDLYD": 6.313392,
    "USDMAD": 9.041151,
    "USDMDL": 16.816366,
    "USDMGA": 4471.14254,
    "USDMKD": 51.667049,
    "USDMMK": 2101.816387,
    "USDMNT": 3580.249923,
    "USDMOP": 8.035377,
    "USDMRU": 40.008586,
    "USDMUR": 45.158538,
    "USDMVR": 15.462816,
    "USDMWK": 1739.631322,
    "USDMXN": 17.193052,
    "USDMYR": 3.918623,
    "USDMZN": 63.725422,
    "USDNAD": 15.829801,
    "USDNGN": 1396.935234,
    "USDNIO": 36.785282,
    "USDNOK": 9.609191,
    "USDNPR": 147.170784,
    "USDNZD": 1.654228,
    "USDOMR": 0.384497,
    "USDPAB": 1,
    "USDPEN": 3.343101,
    "USDPGK": 4.277403,
    "USDPHP": 58.768416,
    "USDPKR": 279.923344,
    "USDPLN": 3.513339,
    "USDPYG": 6725.725173,
    "USDQAR": 3.64,
    "USDRON": 4.253808,
    "USDRSD": 97.999137,
    "USDRUB": 76.344018,
    "USDRWF": 1459.163486,
    "USDSAR": 3.75,
    "USDSBD": 7.967784,
    "USDSCR": 14.153426,
    "USDSDG": 544.164471,
    "USDSEK": 8.8405,
    "USDSGD": 1.262196,
    "USDSHP": 0.724654,
    "USDSLE": 24.320946,
    "USDSLL": 24320.946467,
    "USDSOS": 570.843635,
    "USDSRD": 38.101163,
    "USDSSP": 4619.156454,
    "USDSTN": 20.470386,
    "USDSYP": 113.658694,
    "USDSZL": 15.829801,
    "USDTHB": 31.093452,
    "USDTJS": 9.333489,
    "USDTMT": 3.502138,
    "USDTND": 2.83317,
    "USDTOP": 2.360847,
    "USDTRY": 43.440355,
    "USDTTD": 6.780477,
    "USDTVD": 1.426174,
    "USDTWD": 31.319686,
    "USDTZS": 2548.372041,
    "USDUAH": 42.803345,
    "USDUGX": 3571.732705,
    "USDUYU": 37.593616,
    "USDUZS": 12142.854346,
    "USDVES": 363.6623,
    "USDVND": 26017.593918,
    "USDVUV": 119.117457,
    "USDWST": 2.692888,
    "USDXAF": 548.069102,
    "USDXCD": 2.7,
    "USDXCG": 1.79,
    "USDXDR": 0.71122,
    "USDXOF": 548.069102,
    "USDXPF": 99.704984,
    "USDYER": 238.07384,
    "USDZAR": 15.830167,
    "USDZMW": 19.85584,
    "USDZWG": 25.6259,
    "USDZWL": 25.6259,
    "USDUSD": 1
  }
}
```

### Success Response Format (Single Currency)

The Forex Rates API returns comprehensive currency exchange rate information upon successful request.
```json
{
  "status": "SUCCESS",
  "status_code": "200",
  "status_message": "SUCCESS",
  "mobicard_txn_reference": "794521368",
  "base_currency": "USD",
  "timestamp": "2026-01-29 16:32:15",
  "forex_rates": {
    "USDEUR": 0.835547,
    "USDUSD": 1
  }
}
```
### Response Fields Explanation:

    * status: Always "SUCCESS" or "FAILED" - use this to determine subsequent actions
    * status_code: HTTP status code (200 for success)
    * base_currency: The base currency used for exchange rates (default: USD). Options: (USD, EUR, JPY, GBP, CNY).
    * timestamp: Timestamp when rates were retrieved
    * forex_rates: Object containing currency pair exchange rates
    * forex_rates.USDEUR: Exchange rate from USD to EUR (example: 0.835547 means 1 USD = 0.835547 EUR)
    * forex_rates.USDUSD: Always included with value 1 (base currency to itself)

### Error Response Format

Error responses have a simplified format with only 3 fields of essential information.

Use the "status" field to determine if any API request is successful or not. The value is always either "SUCCESS" or "FAILED".  
```json
{
  "status": "FAILED",
  "status_code": "400",
  "status_message": "BAD REQUEST"
}
```

### Status Codes Reference
Complete list of status codes returned by the API.

| Status Code | Status | Status Message Interpretation | Action Required |
| :--- | :--- | :--- | :--- |
| **200** | `SUCCESS` | SUCCESS - Forex rates retrieved successfully | Process the response data |
| **400** | `FAILED` | BAD REQUEST - Invalid parameters or malformed request | Check request parameters |
| **429** | `FAILED` | TOO MANY REQUESTS - Rate limit exceeded | Wait before making more requests |
| **250** | `FAILED` | INSUFFICIENT TOKENS - Token account balance insufficient | Top up your account |
| **500** | `FAILED` | UNAVAILABLE - Server error | Try again later or contact support |
| **430** | `FAILED` | TIMEOUT - Request timed out | Issue new token and retry |

### API Request Parameters Reference

Complete reference of all request parameters used in the Forex Rates API.

| Parameter | Required | Description | Example Value | Notes |
| :--- | :---: | :--- | :--- | :--- |
| `mobicard_version` | **Yes** | API version | `"2.0"` | Fixed value |
| `mobicard_mode` | **Yes** | Environment mode | `"TEST"` or `"LIVE"` | Use `TEST` for development |
| `mobicard_merchant_id` | **Yes** | Your merchant ID | `""` | Provided by MobiCard |
| `mobicard_api_key` | **Yes** | Your API key | `""` | Provided by MobiCard |
| `mobicard_secret_key` | **Yes** | Your secret key | `""` | Provided by MobiCard |
| `mobicard_service_id` | **Yes** | Service ID | `"20000"` | Fixed value for card services |
| `mobicard_service_type` | **Yes** | Service type | `"FOREXRATES"` | Fixed value |
| `mobicard_token_id` | **Yes** | Unique token identifier | `String/number` | Must be unique per request |
| `mobicard_txn_reference` | **Yes** | Your transaction reference | `String/number` | Your internal reference |
| `mobicard_base_currency` | **No** | Base currency for rates (3-letter ISO code) | `"USD"` | Defaults to "USD" if not provided. Options: (USD, EUR, JPY, GBP, CNY). |
| `mobicard_query_currency` | **No** | Target currency (3-letter ISO code) | `"EUR"` or `""` | Empty returns all currencies, specific code returns single rate |

### API Response Parameters Reference

Complete reference of all response parameters returned by the API.

The value for the "status" response parameter is always either "SUCCESS" or "FAILED". Use this to determine subsequent actions.

| Parameter | Always Returned | Description | Example Value |
| :--- | :---: | :--- | :--- |
| `status` | **Yes** | Transaction status | `"SUCCESS"` or `"FAILED"` |
| `status_code` | **Yes** | HTTP status code | `"200"` |
| `status_message` | **Yes** | Status description | `"SUCCESS"` |
| `mobicard_txn_reference` | **Yes** | Your original transaction reference | `"694329793"` |
| `base_currency` | **Yes** | Base currency used for exchange rates. Options: (USD, EUR, JPY, GBP, CNY). | `"USD"` |
| `timestamp` | **Yes** | Response timestamp | `"2026-01-29 16:31:01"` |
| `forex_rates` | **Yes** | Object containing currency pair exchange rates | `{"USDEUR": 0.835547, "USDUSD": 1}` |
| `forex_rates.[CURRENCY_PAIR]` | **Yes** | Exchange rate for specific currency pair | `0.835547` (for USDEUR) |
| `forex_rates.USDUSD` | **Yes** | Always included with value 1 | `1` |
