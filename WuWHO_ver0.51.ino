//Business Information Systems - BIS4
//WuWHO Wi-Fi probe request interceptor ver0.51
//23-November-2020
//Robert James Hastings - 117757785
//117757785@umail.ucc.ie

//Based on "ESP32 Wi-Fi Sniffer" by Łukasz Podkalicki
//https://github.com/ESP-EOS/ESP32-WiFi-Sniffer 



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
const char* ssid = "VM5190883";
const char* wifipassword =  "CXb3cvk2dpea";

//database server details
IPAddress MySQL_server_address(188,141,18,170); 
char MySQL_user[] = "root";             
char MySQL_password[] = "straylight";  
int MySQL_port = 3306;    

//max num Wi-Fi channels to cycle through
#define maxCh 13 

WiFiClient client;                 
MySQL_Connection conn(&client);
MySQL_Cursor* cursor;

int curChannel = 1;
int cycle = 0;
String rssi_val;
String Insert_Statement = "INSERT INTO WuWHO.tbl_environment_1 (MAC_ID, RSSI, time_rec) VALUES";

const wifi_promiscuous_filter_t filt={ 
    .filter_mask=WIFI_PROMIS_FILTER_MASK_MGMT|WIFI_PROMIS_FILTER_MASK_DATA
};

typedef struct { 
  unsigned char payload[];
} __attribute__((packed)) WifiMgmtHdr;



//____________________Setup__________________________
void setup() {

  Serial.begin(115200); //used for the seriel monitor
 
}

//____________________Packet Sniffer_________________
//Capture data packets and isolate sender MAC address component
void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) { 
  wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t*)buf;
  int len = p->rx_ctrl.sig_len;
  WifiMgmtHdr *wh = (WifiMgmtHdr*)p->payload;
  len -= sizeof(WifiMgmtHdr);
  if (len < 0){
    Serial.println("Received 0");
    return;
  }
  String packet;
  String mac;
  // ignore the first few characters and build up an easy to read packet
  for(int i=8;i<=p->rx_ctrl.sig_len;i++){ 
     packet += String(p->payload[i],HEX);
  }
  for(int i=4;i<=15;i++){ // should leave us the 4 octets of the sender MAC address
    mac += packet[i]; 
  }
  rssi_val = p->rx_ctrl.rssi; //Get the packets RSSI
  
  mac.toUpperCase();
  //for the benifit of debugging using the seriel monitor
  Serial.println("MAC= " + mac + " | RSSI = " + rssi_val); 
  Serial.println(" ");
  //add the current packet to the database insert statement (may adjust this later to use an array)
  Insert_Statement += " ('" + mac + "'," + rssi_val +", now()), "; 
}


//________________Wi-Fi Promiscuous mode_______________
//Set Wi-Fi module for promiscuous mode 
void enter_promiscuous_mode(){
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
  esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
  
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
  if (conn.connect(MySQL_server_address, MySQL_port, MySQL_user, MySQL_password))
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
