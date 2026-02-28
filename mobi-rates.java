import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.Random;
import java.util.HashMap;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

public class MobicardForexRates {
    
    private final String mobicardVersion = "2.0";
    private final String mobicardMode = "TEST";
    private final String mobicardMerchantId;
    private final String mobicardApiKey;
    private final String mobicardSecretKey;
    private final String mobicardServiceId = "20000";
    private final String mobicardServiceType = "FOREXRATES";
    private final String mobicardBaseCurrency = "USD";
    
    private final String mobicardTokenId;
    private final String mobicardTxnReference;
    
    private final Gson gson = new Gson();
    
    public MobicardForexRates(String merchantId, String apiKey, String secretKey) {
        this.mobicardMerchantId = merchantId;
        this.mobicardApiKey = apiKey;
        this.mobicardSecretKey = secretKey;
        
        Random random = new Random();
        this.mobicardTokenId = String.valueOf(random.nextInt(900000000) + 1000000);
        this.mobicardTxnReference = String.valueOf(random.nextInt(900000000) + 1000000);
    }
    
    public String generateJWT(String queryCurrency) throws Exception {
        Map jwtHeader = new HashMap<>();
        jwtHeader.put("typ", "JWT");
        jwtHeader.put("alg", "HS256");
        String encodedHeader = base64UrlEncode(gson.toJson(jwtHeader));
        
        Map jwtPayload = new HashMap<>();
        jwtPayload.put("mobicard_version", mobicardVersion);
        jwtPayload.put("mobicard_mode", mobicardMode);
        jwtPayload.put("mobicard_merchant_id", mobicardMerchantId);
        jwtPayload.put("mobicard_api_key", mobicardApiKey);
        jwtPayload.put("mobicard_service_id", mobicardServiceId);
        jwtPayload.put("mobicard_service_type", mobicardServiceType);
        jwtPayload.put("mobicard_token_id", mobicardTokenId);
        jwtPayload.put("mobicard_txn_reference", mobicardTxnReference);
        jwtPayload.put("mobicard_base_currency", mobicardBaseCurrency);
        jwtPayload.put("mobicard_query_currency", queryCurrency);
        
        String encodedPayload = base64UrlEncode(gson.toJson(jwtPayload));
        
        String headerPayload = encodedHeader + "." + encodedPayload;
        String signature = generateHMAC(headerPayload, mobicardSecretKey);
        
        return encodedHeader + "." + encodedPayload + "." + signature;
    }
    
    public JsonObject getForexRates(String queryCurrency) throws Exception {
        String jwtToken = generateJWT(queryCurrency);
        
        HttpClient client = HttpClient.newHttpClient();
        
        Map requestBody = new HashMap<>();
        requestBody.put("mobicard_auth_jwt", jwtToken);
        
        String jsonBody = gson.toJson(requestBody);
        
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://mobicardsystems.com/api/v1/forex_rates"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();
        
        HttpResponse response = client.send(request, HttpResponse.BodyHandlers.ofString());
        
        return gson.fromJson(response.body(), JsonObject.class);
    }
    
    private String base64UrlEncode(String data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data.getBytes());
    }
    
    private String generateHMAC(String data, String key) throws Exception {
        Mac sha256Hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        sha256Hmac.init(secretKey);
        byte[] hmacBytes = sha256Hmac.doFinal(data.getBytes());
        return base64UrlEncode(new String(hmacBytes));
    }
    
    public static void main(String[] args) {
        try {
            MobicardForexRates forexRates = new MobicardForexRates(
                "4",
                "YmJkOGY0OTZhMTU2ZjVjYTIyYzFhZGQyOWRiMmZjMmE2ZWU3NGIxZWM3ZTBiZSJ9",
                "NjIwYzEyMDRjNjNjMTdkZTZkMjZhOWNiYjIxNzI2NDQwYzVmNWNiMzRhMzBjYSJ9"
            );
            
            // Get all forex rates
            String queryCurrency = ""; // Empty for all currencies
            // Get specific currency rate
            // String queryCurrency = "EUR";
            
            JsonObject result = forexRates.getForexRates(queryCurrency);
            
            if (result.has("status")) {
                String status = result.get("status").getAsString();
                
                if ("SUCCESS".equals(status)) {
                    System.out.println("Forex Rates Retrieved Successfully!");
                    
                    System.out.println("Base Currency: " + 
                        result.get("base_currency").getAsString());
                    System.out.println("Timestamp: " + 
                        result.get("timestamp").getAsString());
                    
                    if (result.has("forex_rates")) {
                        JsonObject rates = result.getAsJsonObject("forex_rates");
                        System.out.println("Total Rates Available: " + 
                            rates.size());
                        
                        System.out.println("\nSample Exchange Rates:");
                        int count = 0;
                        for (String pair : rates.keySet()) {
                            if (count < 5) {
                                System.out.println(pair + ": " + 
                                    rates.get(pair).getAsString());
                                count++;
                            }
                        }
                    }
                } else {
                    System.out.println("Forex Rates Request Failed!");
                    if (result.has("status_message")) {
                        System.out.println("Error: " + result.get("status_message").getAsString());
                    }
                }
            }
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
