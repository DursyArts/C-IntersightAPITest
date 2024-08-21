using System.Formats.Asn1;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;


namespace Simpel {
    public partial class Form1 : Form {
        [DllImport("kernel32")]
        private static extern bool AllocConsole();

        public Form1() {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e) {
            AllocConsole();

            Run();
            //MessageBox.Show(sigB64, Encoding.UTF8.GetString(sig));
        }

        static byte[] ComputeSignature(string a) {
            string stringToSign = a;
            byte[] hashedBytes;
            using ECDsa ecdsakey = ECDsa.Create();

            using(var fileStream = new FileStream("C:\\Users\\Leo\\Documents\\Visual Studio 2022\\Projects\\Cs\\Intersight-CheckAPIKey\\Simpel\\ApiKey\\ApiKey.txt", FileMode.Open, FileAccess.Read)) {
                using(var reader = new StreamReader(fileStream)) {
                    var pem = reader.ReadToEnd();
                    byte[] stringBytes;

                    //Console.WriteLine($"Read PEM as: \n {pem}");chrome://vivaldi-webui/startpage?section=Speed-dials&background-color=#141826

                    try {
                        // Load byte Array with bytes Encoded as UTF8
                        stringBytes = Encoding.UTF8.GetBytes(stringToSign);
                        Console.WriteLine($"Loaded {stringBytes.Length} bytes.");

                        // Use ImportFromPem to load PEM contents into ecdsa object
                        // eg. Curve used, priv & public key
                        ecdsakey.ImportFromPem(pem);

                        // use ecdsa SignData function to sign bytes inside byte array stringBytes using SHA256
                        // and IeeeP1363FFC Format
                        hashedBytes = ecdsakey.SignData(stringBytes, HashAlgorithmName.SHA512, DSASignatureFormat.Rfc3279DerSequence);
                        Console.WriteLine($"##### Hashed bytes using SHA512 as RFC3279 DER sequence:\n{BitConverter.ToString(hashedBytes).Replace("-", "").ToLower()}");

                        // verify data with same inputs
                        bool isValid = ecdsakey.VerifyData(stringBytes, hashedBytes, HashAlgorithmName.SHA512, DSASignatureFormat.Rfc3279DerSequence);
                        Console.WriteLine($"Computed hash valid: {isValid}");
                    } catch(Exception ex) {
                        Console.WriteLine($"Couldnt load key from PEM: {ex}");
                        throw ex;
                    }
                }

                //// load ieee sig
                //byte[] ieeeSignature = hashedBytes;
                //int keySizeInBytes = ecdsakey.KeySize / 8;

                //// split signature into r and s parts equally
                //byte[] r = ieeeSignature[0..keySizeInBytes];
                //byte[] s = ieeeSignature[keySizeInBytes..];

                //// initialize asn writer to correctly format output as ASN.1/DER signature
                //var asnWriter = new AsnWriter(AsnEncodingRules.DER);
                //asnWriter.PushSequence();
                //asnWriter.WriteInteger(r);
                //asnWriter.WriteInteger(s);
                //asnWriter.PopSequence();
                //// save encoded ASN.1/DER Signature
                //byte[] derSignature = asnWriter.Encode();

                //Console.WriteLine($"##### DER signature:\n{BitConverter.ToString(derSignature).Replace("-", "").ToLower()}");
                return hashedBytes;
            }
        }

        //static bool VerifySignature(byte[] derSignature, string dataToVerify, string keyFilePath) {
        //    using(ECDsa ecdsa = ECDsa.Create()) {
        //        // load key
        //        using(var fileStream = new FileStream(keyFilePath, FileMode.Open, FileAccess.Read)) {
        //            using(var reader = new StreamReader(fileStream)) {
        //                var pem = reader.ReadToEnd();

        //                ecdsa.ImportFromPem(pem);
        //            }
        //        }

        //        AsnReader asnReader = new AsnReader(derSignature, AsnEncodingRules.DER);
                
        //    }
        //}



        public static async Task Run() {
            AllocConsole();
            string resourceEndpoint = "https://eu-central-1.intersight.com/api/v1";
            // Create a uri you are going to call.
            var requestUri = new Uri($"{resourceEndpoint}/asset/DeviceContractInformations");
            // Endpoint identities?api-version=2021-03-07 accepts list of scopes as a body
            byte[] body = new byte[0];

            //var serializedBody = JsonConvert.SerializeObject(body);
            var serializedBody = Encoding.UTF8.GetString(body);

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, requestUri) {
                Content = new StringContent(serializedBody, Encoding.UTF8, "application/json")
            };

            static string ComputeContentHash(string content) {
                using var sha256 = SHA256.Create();
                byte[] hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(content));
                //Console.WriteLine(Convert.ToBase64String(hashedBytes));
                var hashString = Convert.ToBase64String(hashedBytes);

                return $"SHA-256={hashString}";
            }

            //static string ComputeSignature(string stringToSign) {
            //    using(var fileStream = new FileStream("C:\\Users\\Leo\\Documents\\Visual Studio 2022\\Projects\\Cs\\Intersight-CheckAPIKey\\Intersight-CheckAPIKey\\Keys\\PrivateKey.pem", FileMode.Open, FileAccess.Read)) {
            //        using(var reader = new StreamReader(fileStream)) {
            //            var pem = reader.ReadToEnd();
            //            //Console.WriteLine($"Read PEM as: \n {pem}");

            //            try {
            //                using var ecdsakey = ECDsa.Create();
            //                ecdsakey.ImportFromPem(pem);

            //                byte[] bytes = Encoding.UTF8.GetBytes(stringToSign);

            //                var hashedBytes = ecdsakey.SignData(bytes, HashAlgorithmName.SHA256);
            //                bool isValid = ecdsakey.VerifyData(bytes, hashedBytes, HashAlgorithmName.SHA256);
                            
            //                return Convert.ToBase64String(hashedBytes);

            //            } catch(Exception ex) {
            //                Console.WriteLine($"Couldnt load key from PEM: {ex}");
            //                throw ex;
            //            }
            //        }
            //    }
            //}

            // Specify the 'x-ms-date' header as the current UTC timestamp according to the RFC1123 standard
            var date = DateTimeOffset.UtcNow.ToString("ddd, dd MMM yyyy HH:mm:ss 'GMT'", CultureInfo.InvariantCulture);
            // Get the host name corresponding with the 'host' header.
            var host = requestUri.Authority;
            // Compute a content hash for the 'x-ms-content-sha256' header.
            var contentHash = ComputeContentHash(serializedBody);

            // Prepare a string to sign.
            string stringToSign = $"(request-target): get {requestUri.PathAndQuery}\ndate: {date}\ndigest:{contentHash}\nhost: {host}";
            //Console.WriteLine($"########### Base string to sign ###########\n{stringToSign}\n########### BASE STRING TO SIGN ###########");
            // key id
            var keyId = "668d65ea7564613305327c62/668d65ea7564613305327c66/66c3ce947564613005b05fc8";
            // Compute the signature.
            var signature = ComputeSignature(stringToSign);

            // Add accept header
            requestMessage.Headers.Add("Accept", "application/json");

            // Concatenate the string, which will be used in the authorization header.
            var authorizationHeader = $"Signature keyId=\"{keyId}\",algorithm=\"hs2019\",headers=\"(request-target) date digest host\",signature=\"{Convert.ToBase64String(signature)}\"";

            // Add an authorization header.
            requestMessage.Headers.Add("Authorization", authorizationHeader);

            // Add a date header.
            requestMessage.Headers.Add("Date", date);

            // Add a host header.
            // In C#, the 'host' header is added automatically by the 'HttpClient'. However, this step may be required on other platforms such as Node.js.
            requestMessage.Headers.Host = host;

            

            // Add a content hash header.
            string contentHeader = contentHash;
            requestMessage.Headers.Add("Digest", contentHeader);

            //Console.WriteLine("########### REQUEST HEADERS ###########\n" + requestMessage.Headers + "########### REQUEST HEADERS ###########");
            using(HttpClient httpClient = new HttpClient { BaseAddress = requestUri }) {
                try {
                    var response = await httpClient.SendAsync(requestMessage);
                    var responseString = await response.Content.ReadAsStringAsync();
                    Console.WriteLine(responseString);
                } catch(Exception ex) {
                    Console.WriteLine("error on sending: " + ex);
                }

                
            };
            
            
            
        }

        // the signature is In HEX!!!!
        // for testing
        

        //static void Bouncy() {
        //    string pemPath = @"C:\\Users\\Leo\\Documents\\Visual Studio 2022\\Projects\\Cs\\Intersight-CheckAPIKey\\Intersight-CheckAPIKey\\Keys\\PrivateKey.pem";
        //    string pemContent = File.ReadAllText(pemPath);
        //    Console.WriteLine("Test 1");
        //    PemReader pemReader = new PemReader(new StringReader(pemContent));
            
        //    object pemObject;
        //    try {
        //        pemObject = pemReader.ReadObject();
        //        try {
        //            AsymmetricCipherKeyPair keyPair = pemObject as AsymmetricCipherKeyPair;
        //            if(keyPair != null) {
        //                Console.WriteLine("Loaded AsymmetricCipherKeyPair:");
        //                Console.WriteLine(keyPair.Private);
        //            }
        //        } catch(Exception ex) {
        //            Console.WriteLine($"Error getting keypair: {ex}");
        //        }

                
        //    } catch(Exception ex) {
        //        Console.WriteLine($"Error reading pem file: {ex}");
        //    }

            
            
        //}
    }
}
