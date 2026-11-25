import os
import sys
import json
import pytest

moduleDir=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0,os.path.join(moduleDir,"scripts"))
import annotate_ppg as a

sampleApp="org.fdroid.fdroid@1021051-b6465184"
ppgDir=os.path.join(moduleDir,"output","ppg",sampleApp)
apgDir=os.path.join(moduleDir,"output","apg",sampleApp)
sensMap=a.loadMap(os.path.join(moduleDir,"config","sensitivity_map.json"))

javaSample="""    private void readLocation(android.location.LocationManager p1)
    {
        if (androidx.core.content.ContextCompat.checkSelfPermission(this, "android.permission.ACCESS_FINE_LOCATION") == 0) {
            android.location.Location v0_1 = p1.getLastKnownLocation("gps");
            double v1_2 = v0_1.getLatitude();
            String v2_3 = String.valueOf(v1_2);
            this.send(v2_3);
        }
        return;
    }"""

def testDescribe():
    assert a.describe("org.fdroid.fdroid.nearby.SwapWorkflowActivity.checkIfNewRepoOnSameWifi")=="Check if new repo on same wifi"
    assert a.describe("org.fdroid.fdroid.nearby.WifiStateChangeService$WifiInfoThread.run")=="Wifi info thread"

def testApiName():
    assert a.apiName("<android.net.wifi.WifiInfo: java.lang.String getBSSID()>")=="getBSSID"
    assert a.apiName("not a signature") is None

def testFindAssigned():
    assert a.findAssigned("        int v0_3 = x.getBSSID();")==("v0_3","x.getBSSID();")
    assert a.findAssigned("        if (v0_3 == null) {")==(None,None)
    assert a.findAssigned("        return v0_3;")==(None,None)

def testClassify():
    assert a.classify("phone number","UNIQUE_IDENTIFIER",sensMap)["level"]=="identifier"
    assert a.classify("made up type","LOCATION_INFORMATION",sensMap)["level"]=="quasi_identifier"
    assert a.classify("made up type","MADE_UP",sensMap)["level"]=="unknown"

def testEveryLevelIsKnown():
    for table in ["data_types","categories"]:
        for name in sensMap[table]:
            assert sensMap[table][name]["level"] in a.levelOrder

def testColors():
    code,returnVars,flowVars=a.colorCode(javaSample, ["getLastKnownLocation"])
    assert returnVars==["v0_1"]
    assert "v1_2" in flowVars and "v2_3" in flowVars
    assert '<span class="red">getLastKnownLocation</span>' in code
    assert '<span class="blue">readLocation</span>' in code
    assert '<span class="perm">checkSelfPermission</span>' in code
    assert 'class="perm">&quot;android.permission.ACCESS_FINE_LOCATION&quot;' in code
    assert '<span class="orange">v0_1</span>' in code
    assert '<span class="green">v2_3</span>' in code

@pytest.mark.skipif(not os.path.isdir(ppgDir),reason="sample PPGs not exported")
def testSampleApp(tmp_path):
    requested,app=a.loadManifest(apgDir)
    methodPpgs,flowPpgs=a.readPpgs(ppgDir)
    assert len(methodPpgs)==12
    for ppg in methodPpgs:
        l=a.labelPpg(ppg, flowPpgs, requested, sensMap)
        assert l["code"].count('class="blue"')==1
        assert l["code"].count('class="red"')>=1
        for d in l["data"]:
            assert d["level"]!="unknown"
        for p in l["permissions"]:
            assert p["declared_in_manifest"]

@pytest.mark.skipif(not os.path.isdir(ppgDir),reason="sample PPGs not exported")
def testSampleSinks():
    requested,app=a.loadManifest(apgDir)
    methodPpgs,flowPpgs=a.readPpgs(ppgDir)
    for ppg in methodPpgs:
        if ppg["method"].endswith("WifiStateChangeService.setSsid"):
            l=a.labelPpg(ppg, flowPpgs, requested, sensMap)
            kinds=[]
            for s in l["sinks"]:
                kinds.append(s["kind"])
            assert "url" in kinds
            assert "ui_display" in kinds
