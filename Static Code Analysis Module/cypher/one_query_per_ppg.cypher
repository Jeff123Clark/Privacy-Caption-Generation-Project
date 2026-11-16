// =============================================================================
// One Cypher query per PPG: F-Droid's 12 PPGs.
// Each query takes one method's APG and returns its PPG as a graph: the method,
// its sensitive calls, the Android APIs they call, where the data goes inside the
// method (DATA_DEP) and the ifs that decide whether it is read (CONTROL_DEP).
// Needs the SourceAPI labels (walkthrough step 2, or scripts/build_ppg.py).
// Paste one query into Neo4j Browser; untick "Connect result nodes" for a clean view.
// =============================================================================

// PPG 1: org.fdroid.fdroid.nearby.WifiStateChangeService.setSsid  (Wi-Fi network name, access point ID)
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184'})
WHERE m.class_name + '.' + m.name = 'org.fdroid.fdroid.nearby.WifiStateChangeService.setSsid'
MATCH (m)-[:HAS_STATEMENT]->(src:Statement)-[call:INVOKES]->(api:SourceAPI)
WHERE api.source_list = 'curated'
OPTIONAL MATCH flow = (src)-[:DATA_DEP*1..6]->(use:Statement)<-[:HAS_STATEMENT]-(m)
OPTIONAL MATCH (cond:Statement)-[cd:CONTROL_DEP]->(src)
RETURN m, src, call, api, flow, cond, cd;

// PPG 2: org.fdroid.fdroid.nearby.WifiStateChangeService$WifiInfoThread.run  (IP address, DHCP information)
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184'})
WHERE m.class_name + '.' + m.name = 'org.fdroid.fdroid.nearby.WifiStateChangeService$WifiInfoThread.run'
MATCH (m)-[:HAS_STATEMENT]->(src:Statement)-[call:INVOKES]->(api:SourceAPI)
WHERE api.source_list = 'curated'
OPTIONAL MATCH flow = (src)-[:DATA_DEP*1..6]->(use:Statement)<-[:HAS_STATEMENT]-(m)
OPTIONAL MATCH (cond:Statement)-[cd:CONTROL_DEP]->(src)
RETURN m, src, call, api, flow, cond, cd;

// PPG 3: org.fdroid.fdroid.nearby.SwapWorkflowActivity.checkIfNewRepoOnSameWifi  (Wi-Fi access point ID)
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184'})
WHERE m.class_name + '.' + m.name = 'org.fdroid.fdroid.nearby.SwapWorkflowActivity.checkIfNewRepoOnSameWifi'
MATCH (m)-[:HAS_STATEMENT]->(src:Statement)-[call:INVOKES]->(api:SourceAPI)
WHERE api.source_list = 'curated'
OPTIONAL MATCH flow = (src)-[:DATA_DEP*1..6]->(use:Statement)<-[:HAS_STATEMENT]-(m)
OPTIONAL MATCH (cond:Statement)-[cd:CONTROL_DEP]->(src)
RETURN m, src, call, api, flow, cond, cd;

// PPG 4: org.fdroid.fdroid.nearby.BluetoothManager$1.onLooperPrepared  (Bluetooth name, paired devices)
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184'})
WHERE m.class_name + '.' + m.name = 'org.fdroid.fdroid.nearby.BluetoothManager$1.onLooperPrepared'
MATCH (m)-[:HAS_STATEMENT]->(src:Statement)-[call:INVOKES]->(api:SourceAPI)
WHERE api.source_list = 'curated'
OPTIONAL MATCH flow = (src)-[:DATA_DEP*1..6]->(use:Statement)<-[:HAS_STATEMENT]-(m)
OPTIONAL MATCH (cond:Statement)-[cd:CONTROL_DEP]->(src)
RETURN m, src, call, api, flow, cond, cd;

// PPG 5: org.fdroid.fdroid.nearby.StartSwapView.uiInitBluetooth  (Bluetooth name)
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184'})
WHERE m.class_name + '.' + m.name = 'org.fdroid.fdroid.nearby.StartSwapView.uiInitBluetooth'
MATCH (m)-[:HAS_STATEMENT]->(src:Statement)-[call:INVOKES]->(api:SourceAPI)
WHERE api.source_list = 'curated'
OPTIONAL MATCH flow = (src)-[:DATA_DEP*1..6]->(use:Statement)<-[:HAS_STATEMENT]-(m)
OPTIONAL MATCH (cond:Statement)-[cd:CONTROL_DEP]->(src)
RETURN m, src, call, api, flow, cond, cd;

// PPG 6: org.fdroid.fdroid.nearby.StartSwapView$2.onCheckedChanged  (Bluetooth name)
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184'})
WHERE m.class_name + '.' + m.name = 'org.fdroid.fdroid.nearby.StartSwapView$2.onCheckedChanged'
MATCH (m)-[:HAS_STATEMENT]->(src:Statement)-[call:INVOKES]->(api:SourceAPI)
WHERE api.source_list = 'curated'
OPTIONAL MATCH flow = (src)-[:DATA_DEP*1..6]->(use:Statement)<-[:HAS_STATEMENT]-(m)
OPTIONAL MATCH (cond:Statement)-[cd:CONTROL_DEP]->(src)
RETURN m, src, call, api, flow, cond, cd;

// PPG 7: org.fdroid.fdroid.nearby.peers.BluetoothPeer.getInstance  (nearby device name)
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184'})
WHERE m.class_name + '.' + m.name = 'org.fdroid.fdroid.nearby.peers.BluetoothPeer.getInstance'
MATCH (m)-[:HAS_STATEMENT]->(src:Statement)-[call:INVOKES]->(api:SourceAPI)
WHERE api.source_list = 'curated'
OPTIONAL MATCH flow = (src)-[:DATA_DEP*1..6]->(use:Statement)<-[:HAS_STATEMENT]-(m)
OPTIONAL MATCH (cond:Statement)-[cd:CONTROL_DEP]->(src)
RETURN m, src, call, api, flow, cond, cd;

// PPG 8: org.fdroid.fdroid.nearby.peers.BluetoothPeer.getName  (nearby device name)
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184'})
WHERE m.class_name + '.' + m.name = 'org.fdroid.fdroid.nearby.peers.BluetoothPeer.getName'
MATCH (m)-[:HAS_STATEMENT]->(src:Statement)-[call:INVOKES]->(api:SourceAPI)
WHERE api.source_list = 'curated'
OPTIONAL MATCH flow = (src)-[:DATA_DEP*1..6]->(use:Statement)<-[:HAS_STATEMENT]-(m)
OPTIONAL MATCH (cond:Statement)-[cd:CONTROL_DEP]->(src)
RETURN m, src, call, api, flow, cond, cd;

// PPG 9: org.fdroid.fdroid.nearby.peers.BluetoothPeer.getRepoAddress  (nearby device address)
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184'})
WHERE m.class_name + '.' + m.name = 'org.fdroid.fdroid.nearby.peers.BluetoothPeer.getRepoAddress'
MATCH (m)-[:HAS_STATEMENT]->(src:Statement)-[call:INVOKES]->(api:SourceAPI)
WHERE api.source_list = 'curated'
OPTIONAL MATCH flow = (src)-[:DATA_DEP*1..6]->(use:Statement)<-[:HAS_STATEMENT]-(m)
OPTIONAL MATCH (cond:Statement)-[cd:CONTROL_DEP]->(src)
RETURN m, src, call, api, flow, cond, cd;

// PPG 10: org.fdroid.fdroid.nearby.SelectAppsView.onFinishInflate  (installed apps)
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184'})
WHERE m.class_name + '.' + m.name = 'org.fdroid.fdroid.nearby.SelectAppsView.onFinishInflate'
MATCH (m)-[:HAS_STATEMENT]->(src:Statement)-[call:INVOKES]->(api:SourceAPI)
WHERE api.source_list = 'curated'
OPTIONAL MATCH flow = (src)-[:DATA_DEP*1..6]->(use:Statement)<-[:HAS_STATEMENT]-(m)
OPTIONAL MATCH (cond:Statement)-[cd:CONTROL_DEP]->(src)
RETURN m, src, call, api, flow, cond, cd;

// PPG 11: org.fdroid.fdroid.work.FDroidMetricsWorker.generateReport  (installed apps)
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184'})
WHERE m.class_name + '.' + m.name = 'org.fdroid.fdroid.work.FDroidMetricsWorker.generateReport'
MATCH (m)-[:HAS_STATEMENT]->(src:Statement)-[call:INVOKES]->(api:SourceAPI)
WHERE api.source_list = 'curated'
OPTIONAL MATCH flow = (src)-[:DATA_DEP*1..6]->(use:Statement)<-[:HAS_STATEMENT]-(m)
OPTIONAL MATCH (cond:Statement)-[cd:CONTROL_DEP]->(src)
RETURN m, src, call, api, flow, cond, cd;

// PPG 12: org.fdroid.database.DbUpdateChecker.getUpdatableApps  (installed apps)
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184'})
WHERE m.class_name + '.' + m.name = 'org.fdroid.database.DbUpdateChecker.getUpdatableApps'
MATCH (m)-[:HAS_STATEMENT]->(src:Statement)-[call:INVOKES]->(api:SourceAPI)
WHERE api.source_list = 'curated'
OPTIONAL MATCH flow = (src)-[:DATA_DEP*1..6]->(use:Statement)<-[:HAS_STATEMENT]-(m)
OPTIONAL MATCH (cond:Statement)-[cd:CONTROL_DEP]->(src)
RETURN m, src, call, api, flow, cond, cd;
