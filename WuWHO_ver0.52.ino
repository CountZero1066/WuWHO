//Business Information Systems - BIS4
//WuWHO Wi-Fi probe request interceptor ver0.51
//23-November-2020
//Robert James Hastings - 117757785
//117757785@umail.ucc.ie

//Inspired by "ESP32 Wi-Fi Sniffer" by Łukasz Podkalicki
//https://github.com/ESP-EOS/ESP32-WiFi-Sniffer 

//Built using the ESPRESSIF Wi-Fi API
//https://github.com/espressif/arduino-esp32/blob/master/tools/sdk/include/esp32/esp_wifi.h
//https://docs.espressif.com/projects/esp-idf/en/release-v4.2/esp32/api-reference/network/esp_wifi.html



//_________________libraries__________________ 
#include <WiFi.h>
#include <Wire.h>
#include <string.h>
#include <stdio.h>
#include "esp_wifi.h" 
#include <MySQL_Connection.h>
#include <MySQL_Cursor.h>

//________________Declaring Variables__________
//local AP details
const char* ssid = "###########";               //Network SSID goes here
const char* wifipassword =  "###########";      //Network password goes here

//database server details
IPAddress MySQL_server_address(###,###,##,###); //IP address of database server goes here
char MySQL_user[] = "###########";              //database username goes here
char MySQL_password[] = "###########";          //database password goes here
int MySQL_port = 3306;                          //Port number database server is listening to goes here

//max num Wi-Fi channels to cycle through
#define maxCh 13 

WiFiClient client;                 
MySQL_Connection conn(&client);
MySQL_Cursor* cursor;

int curChannel = 1;
int cycle = 0;
String rssi_val;
String Insert_Statement = "INSERT INTO WuWHO.tbl_environment_1 (MAC_ID, RSSI, time_rec) VALUES";

//define the type of packet we're filtering for, which are management frames
const wifi_promiscuous_filter_t filt={ 
    .filter_mask=WIFI_PROMIS_FILTER_MASK_MGMT|WIFI_PROMIS_FILTER_MASK_DATA
};
//used to contain packet 
//I'm not sure how big the packet will be, but 5,000 characters should be more than enough
  unsigned char payload[5000];




//____________________Setup__________________________
void setup() {

  Serial.begin(115200); //used for the seriel monitor
 
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
  //for the benifit of debugging using the seriel monitor
  Serial.println("MAC= " + mac + " | RSSI = " + rssi_val); 
  Serial.println(" ");
  //add the current packet to the database insert statement (may adjust this later to use an array)
  Insert_Statement += " ('" + mac + "'," + rssi_val +", now()), "; 
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
}

//______________Standard Wi-Fi mode___________________
//Connect to local accesss point in normal Wi-Fi mode
void wifi_connect_to_network(){
  WiFi.begin(ssid, wifipassword);
 
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.println("Trying to start normal Wi-Fi mode and connect to AP...");
}
Serial.println("Succeeded in connecting to the AP");
  }

 //_____________Connect to MySQL database server___________
//Connect to MySQL database server
void connect_to_mysql(){

 Serial.print("Connecting to MySQL Database Server...  ");
  if (conn.connect(MySQL_server_address, MySQL_port, MySQL_user, MySQL_password)) //are we connected to the database?
    Serial.println("CONNECTION TO DATABASE SERVER SUCCESSFUL.");
  else
    Serial.println("FAILED TO CONNECT TO DATABASE SERVER.");
  
  // create MySQL cursor object
  cursor = new MySQL_Cursor(&conn);
  
}


//__________________Main Program Loop_______________________
void loop() {

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
  wifi_connect_to_network();
  connect_to_mysql();

   
   Insert_Statement += "('end of statement', 0, now()); ";
   char sql_insert_stat[5000];
   strncpy(sql_insert_stat, Insert_Statement.c_str(), sizeof(sql_insert_stat));
   sql_insert_stat[sizeof(sql_insert_stat)-1] ='\0';

  
   if (conn.connected())
    cursor->execute(sql_insert_stat);

  delay(2000); //without this delay, I'm pretty sure the ESP32 would catch fire
  //reset the INSERT statement for the next cycle
  Insert_Statement = "INSERT INTO WuWHO.tbl_environment_1 (MAC_ID, RSSI, time_rec) VALUES"; 
  WiFi.mode(WIFI_OFF); // preparation for re-entry into promiscuous mode
    
}
