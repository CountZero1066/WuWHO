//Business Information Systems - BIS4
//WuWHO Wi-Fi probe request interceptor ver0.7.1
//10-March-2021
//Robert James Hastings - 117757785
//117757785@umail.ucc.ie

//Inspired "ESP32 Wi-Fi Sniffer" by Łukasz Podkalicki
//https://github.com/ESP-EOS/ESP32-WiFi-Sniffer 

//Built using the ESPRESSIF Wi-Fi API
//https://github.com/espressif/arduino-esp32/blob/master/tools/sdk/include/esp32/esp_wifi.h
//https://docs.espressif.com/projects/esp-idf/en/release-v4.2/esp32/api-reference/network/esp_wifi.html


/*
 * ###############################################################
 * #                 Iteration 5: Details                        #
 * # Included Bluetooth serial communication for user input of   #
 * # local AP credentials and saving them to the ESP32s          #    
 * # nonvolatile flash memory. At startup, flash memory is       #
 * # checked for existing credentials and tested, if no          #
 * # credentials are found, user is prompted to enter them       #                                               
 * ###############################################################
*/

//_________________libraries__________________ 
#include <WiFi.h>
#include <Wire.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "esp_wifi.h" 
#include <MySQL_Connection.h>
#include <MySQL_Cursor.h>
#include <Adafruit_SSD1306.h>
#include <Adafruit_GFX.h>
#include <SPI.h>
#include "mbedtls/md.h"
#include <Preferences.h>
#include "BluetoothSerial.h"



BluetoothSerial SerialBT;
Preferences preferences;

//________________Declaring Variables__________

String bt_ssid;
String bt_password;
String mem_ssid;
String mem_pass;

//database server details
IPAddress MySQL_server_address(188,141,18,170); 
char MySQL_user[] = "test_client_user";             
char MySQL_password[] = "tcuFYP2021";  
int MySQL_port = 1177;    

//max num Wi-Fi channels to cycle through
#define maxCh 13 

WiFiClient client;                 
MySQL_Connection conn(&client);
MySQL_Cursor* cursor;

int ledred = 15;
int ledgreen =23;
int curChannel = 1;
int cycle = 0;
String rssi_val;
String Insert_Statement = "INSERT INTO WuWHO.tbl_environment_4 (MAC_ID, RSSI, time_rec) VALUES";

//define the type of packet we're filtering for, which are management frames
const wifi_promiscuous_filter_t filt={ 
    .filter_mask=WIFI_PROMIS_FILTER_MASK_MGMT|WIFI_PROMIS_FILTER_MASK_DATA
};
//used to contain packet 
//I'm not sure how big the packet will be, but 5,000 characters should be more than enough
  unsigned char payload[5000];

//setting up SSD1306 13C 128x32 pixel OLED display

#define SCREEN_WIDTH 128 
#define SCREEN_HEIGHT 32 
#define OLED_RESET     4
#define SCREEN_ADDRESS 0x3C
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
Adafruit_SSD1306 oled(0x3c, 21, 22);  //   I2C address, SDA, SCL

//____________________Setup__________________________
void setup() {

  Serial.begin(9600); //used for the serial monitor
  pinMode(ledred, OUTPUT);
  pinMode(ledgreen, OUTPUT);
  digitalWrite(ledgreen, HIGH);

  SerialBT.begin("WuWHO bt"); //Bluetooth device name
  Serial.println("Bluetooth ready");
    preferences.begin("wifi_cred", false);
    
  
if(!display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS)) {
    Serial.println(F("SSD1306 allocation failed"));
    for(;;); // Don't proceed, loop forever
  }
   
   display.display();
     delay(2000); // Pause for 2 seconds
     display.clearDisplay();

     display.drawPixel(10, 10, SSD1306_WHITE);

   display.display();
   delay(2000);
   
   LCD_Display("WuWHO",2000, 3);
   LCD_Display("BIS 2021", 1000, 2);
   display.clearDisplay();
   delay(2000);
   LCD_Display("checking memory", 500, 1);
   
    check_for_WiFi_cred();

    LCD_Display("starting...", 2000, 1);
}

//____________________Check Flash for Existing Credentials_____________________
void check_for_WiFi_cred(){
  mem_ssid = preferences.getString("flash_ssid", ""); 
  mem_pass = preferences.getString("flash_password", "");
  delay(2000);
  if (mem_ssid == "" || mem_pass == ""){
    Serial.println("No credentials found");
    Serial.println("Enter New Credentials via Bluetooth");
    LCD_Display("Enter WiFi credentials via Bluetooth", 2000, 1);
    bluetooth_com_SSID();
  }
  else{
    LCD_Display("Found Saved        Credentials", 1500, 1);
    Serial.println("Testing discovered Credentials");
  wifi_test_network(mem_ssid, mem_pass, false);
}
}


//____________________Read WiFi SSID from Bluetooth Serial______________________
void bluetooth_com_SSID(){
  LCD_Display("Enter SSID", 1000, 1);
  SerialBT.println("Enter Network SSID");
  if (Serial.available()) {
    SerialBT.println("Enter Network SSID");
  }
  while(bt_ssid.length() < 1){
    if (SerialBT.available()) {
    bt_ssid = SerialBT.readString();
  
    if(bt_ssid.length() > 1){
      Serial.println(bt_ssid);
    
    SerialBT.println("Network SSID = " + bt_ssid );
    } 
    bluetooth_com_password();
  }
  }
  
}
//____________________Read WiFi PW from Bluetooth Serial________________________
void bluetooth_com_password(){
  LCD_Display("Enter Password", 1000, 1);
  SerialBT.println("Enter Network password");
  if (Serial.available()) {
    SerialBT.println("Enter Network password");
  }
  while(bt_password.length() < 1){
    if (SerialBT.available()) {
    bt_password = SerialBT.readString();
  
    if(bt_password.length() > 1){
      Serial.println(bt_password);
    
    SerialBT.println("Network Password = " + bt_password );
    }
  }
  }
  SerialBT.println("Press 1 to re-enter Wi-Fi credentials or 2 to continue");
  Re_enter_net_cred();
}


//____________________Confirm Entered WiFi Credentials Logic Branch______________
void Re_enter_net_cred(){
 int try_again;
 char temp_str[2];
 String temp_str_2;
 
  while(temp_str_2.length() < 1){

    if (SerialBT.available()) {
      temp_str_2 = SerialBT.readString();
      strcpy(temp_str, temp_str_2.c_str()); 
      try_again = atoi(temp_str);
    
    switch(try_again){
        case 1 :
        SerialBT.println("Re-entering Wi-Fi credentials");
        bt_ssid = ""; //set bt_ssid & bt_password to nothing because their respective functions won't loop unless they're flsuhed
        bt_password = "";
        temp_str_2 = "";
        bluetooth_com_SSID();
        break;

        case 2 : //only selection that'll allow the program to escape from this function
        SerialBT.println("Testing Wi-Fi Connection");
        wifi_test_network(bt_ssid, bt_password, true);
        break;

        default :
        SerialBT.println("Invalid Selection");
        Serial.println("Invalid selection");
        temp_str_2 = ""; //while loop controled by the length of temp_str_2, clearing temp_str_2 prevents program from breaking out of the loop
        break;
    }

   }
  
  }
   temp_str_2 = "";
}


//____________________Format Bluetooth Serial Input Data_______________
String format_AP_creds(String string_to_format){
   String shave_whitespace;

    int i = 0; 
    int char_to_count = string_to_format.length() - 2;

    for (i = 0; i < char_to_count; i++)
    { 
           shave_whitespace += string_to_format[i]; 
    }
    return shave_whitespace;
}

//____________________Test WiFi Credentials____________________________
void wifi_test_network(String ssid, String wifipassword, bool convert){

String formatted_ssid;
String formatted_password;

if(convert == true){
 formatted_ssid = format_AP_creds(ssid);
 formatted_password = format_AP_creds(wifipassword);
}else{
  formatted_ssid = ssid;
  formatted_password = wifipassword;
}

 WiFi.begin(formatted_ssid.c_str(), formatted_password.c_str());
 int attempt_loop=0;

  while ((WiFi.status() != WL_CONNECTED) && (attempt_loop < 20)) {
    LCD_Display("testing...", 10, 1);
    delay(500);
    Serial.println("Testing Wi-Fi conn");
    SerialBT.println("Testing");
    attempt_loop++; 
    
}
if(WiFi.status() == WL_CONNECTED){
  LCD_Display("AP connect OK", 1000, 1);
  Serial.println("Succeeded in connecting to the AP");
  SerialBT.println("connected to AP");
   preferences.putString("flash_ssid", formatted_ssid); 
   preferences.putString("flash_password", formatted_password);
   delay(1000);
     SerialBT.println("WiFi credentials saved");
     WiFi.mode(WIFI_OFF);

}else{
  LCD_Display("Failed to connect", 1000, 1);
  Serial.println("Failed to connect to the AP");
  SerialBT.println("failed to connect");
  bt_ssid = "";
  bt_password = "";
  bluetooth_com_SSID();
}


  }

//___________________SHA 256_______________________
 String Hash_data(char mac_string[]){

  char *payload = mac_string;
  byte shaResult[32];
 
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
 
  const size_t payloadLength = strlen(payload);         
 
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, (const unsigned char *) payload, payloadLength);
  mbedtls_md_finish(&ctx, shaResult);
  mbedtls_md_free(&ctx);
 
 String string_hash;
  for(int i= 0; i< sizeof(shaResult); i++){
      char str[3];
 
      sprintf(str, "%02x", (int)shaResult[i]);
      string_hash += str;
} 
return string_hash;
}



//____________________LCD____________________________
void LCD_Display(String DisplayText, int TimeDelay, int TextScale) {
 
  display.clearDisplay();

  display.setTextSize(TextScale);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(10, 0);
  display.println(DisplayText);
  display.display();
  delay(TimeDelay);

}

//____________________Packet Sniffer_________________
//Interogate data packets and isolate sender MAC address component
void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) { //passing the captured packet stored in the buffer 
  wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t*)buf;
  
  String packet;
  String mac;
  // ignore the first few characters and build up an easy to read packet
  for(int i=8;i<=p->rx_ctrl.sig_len;i++){ // management payload length is described by rx_ctrl.sig_len
     packet += String(p->payload[i],HEX);
  }
  
  for(int i=4;i<=15;i++){ // should leave us the 4 octets of the sender MAC address
    mac += packet[i]; 
  }
  rssi_val = p->rx_ctrl.rssi; //Get the frames RSSI
  
  mac.toUpperCase();
  char mac_array[64];
  strncpy(mac_array, mac.c_str(), sizeof(mac_array));

  String hashed;
  hashed = Hash_data(mac_array);
  //for the benifit of debugging using the seriel monitor
 // Serial.println("MAC= " + mac + " | RSSI = " + rssi_val); 
  Serial.println("hashed data= " + hashed);
  //add the current packet to the database insert statement (may adjust this later to use an array)
  Insert_Statement += " ('" + hashed + "'," + rssi_val +", now()), "; 
}


//________________Wi-Fi Promiscuous mode_______________
//Set Wi-Fi module for promiscuous mode and capture data packets
void enter_promiscuous_mode(){
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT(); //used to initialise the Wi_Fi configuration to default values
  esp_wifi_init(&cfg); //calls the Wi_Fi API and sets config to default 
  esp_wifi_set_storage(WIFI_STORAGE_FLASH); //Set the API storage to flash, can also be stored in RAM
  esp_wifi_set_mode(WIFI_MODE_NULL);//set Wi_Fi to null mode, allows the internal data struct to not be allocated to the AP 
  esp_wifi_start();
  esp_wifi_set_promiscuous(true); //allows data packets to be accessed and viewed by the device
  esp_wifi_set_promiscuous_filter(&filt); //sets the packet type we're going to be filtering for.
  esp_wifi_set_promiscuous_rx_cb(&sniffer); //call the sniffer function 
  esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE); //switch Wi-Fi channel
  
  Serial.println("Entering Promiscuous Mode");
  LCD_Display("Scanning", 1000, 2);
}

//______________Standard Wi-Fi mode___________________
//Connect to local accesss point in normal Wi-Fi mode
void wifi_connect_to_network(){
 
  WiFi.begin(mem_ssid.c_str(), mem_pass.c_str());
 
  while (WiFi.status() != WL_CONNECTED) { 
    digitalWrite(ledred, HIGH);
    delay(500);
    digitalWrite(ledred, LOW);
    Serial.println("Trying to start normal Wi-Fi mode and connect to AP...");
    LCD_Display("Connect  to AP", 1500, 2);
}
    digitalWrite(ledred, HIGH);

Serial.println("Succeeded in connecting to the AP");
LCD_Display("AP Conn  Success",1000, 2);
    digitalWrite(ledred, LOW);


  }

 //_____________Connect to MySQL database server___________
//Connect to MySQL database server
void connect_to_mysql(){

 Serial.print("Connecting to MySQL Database Server...  ");
 LCD_Display("Connect  to DB", 1500, 2);
 
  if (conn.connect(MySQL_server_address, MySQL_port, MySQL_user, MySQL_password)) //are we connected to the database?
    
    LCD_Display("Success!",1000, 2);
  else
   
    LCD_Display("Failed",8000, 2);
  
  // create MySQL cursor object
  cursor = new MySQL_Cursor(&conn);
  
}


//__________________Main Program Loop_______________________
void loop() {
//Hash_data();

enter_promiscuous_mode();
  
  int cycle = 0;
  while(cycle < 1){
  
    Serial.println("Changed channel:" + String(curChannel));
   
    if(curChannel > maxCh){ 
      curChannel = 1;
      cycle++;
    }
    esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
    delay(1000);   
    curChannel++;
    Serial.println("cycle =" + String(cycle));
  }
  esp_wifi_set_promiscuous(false);
  esp_wifi_stop();
  digitalWrite(ledgreen, LOW);
  wifi_connect_to_network();
  digitalWrite(ledgreen, HIGH);
  connect_to_mysql();

   
   Insert_Statement += "('end of statement', 0, now()); ";
   char sql_insert_stat[6000];
   strncpy(sql_insert_stat, Insert_Statement.c_str(), sizeof(sql_insert_stat));
   sql_insert_stat[sizeof(sql_insert_stat)-1] ='\0';

  
   if (conn.connected())
    cursor->execute(sql_insert_stat);
    
    
  delay(2000); //without this delay, I'm pretty sure the ESP32 would catch fire
  //reset the INSERT statement for the next cycle
  Insert_Statement = "INSERT INTO WuWHO.tbl_environment_4 (MAC_ID, RSSI, time_rec) VALUES"; 
 // ESP.restart();
  WiFi.mode(WIFI_OFF); // preparation for re-entry into promiscuous mode
    
}
