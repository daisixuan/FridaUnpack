var opencommon_addr;
var dexfile_dexfile_addr;
var LoadMethod_addr;
var Execute_addr;
var dex_maps = {};

function getAppDataPath() {
    var path;
    // Java.perform(function () {
    //     var context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
    //     var name = context.getPackageName()
    //     path = "/data/data/" + name
    // })
    if (!path) {
        path = "/sdcard"
    }
    path = "/sdcard"

    return path

}


function FindArtAddr() {
    var symbols = Process.getModuleByName("libart.so").enumerateSymbols();
    //var opencommon_addr = Module.findExportByName("libart.so","_ZN3art7DexFile10OpenCommonEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_PNS0_12VerifyResultE")
    // _ZN3art7DexFileC2EPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileE
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        if (symbol.name.indexOf("OpenCommon") >= 0) {
            opencommon_addr = symbol.address
        }
        if (symbol.name.indexOf("DexFileC2") >= 0
            && symbol.name.indexOf("OatDexFileE") >= 0
        ) {
            //console.log(JSON.stringify(symbol))
            dexfile_dexfile_addr = symbol.address
        }
        if (symbol.name.indexOf("ClassLinker") >= 0
        && symbol.name.indexOf("LoadMethod") >= 0
        ) {
            //console.log(JSON.stringify(symbol))
            LoadMethod_addr = symbol.address
        }
        if (symbol.name.indexOf("Execute") >= 0
            && symbol.name.indexOf("interpreter") >= 0
            && symbol.name.indexOf("SwitchImpl") < 0
        ) {
            //console.log(JSON.stringify(symbol))
            Execute_addr = symbol.address
        }
    }
    hook_OpenCommon()
    hook_DexFile_DexFile()
    //hook_LoadMethod()
    //hook_Execute()
}

function hook_OpenCommon() {
    if (opencommon_addr) {
        console.log("opencommon_addr", opencommon_addr);
        Interceptor.attach(opencommon_addr, {
            onEnter: function (args) {
                this.base = ptr(args[1])//.add(Process.pointerSize * 1).readPointer();
                this.size = parseInt(args[2], 16)
                //var size = ptr(parseInt(base,16) + 0x20).readInt() // 通过dex格式来计算出size
            }, onLeave: function (retval) {
                //dex_maps[this.size] = {"base":this.base,"size":this.size};
                var name = "OpenCommon_" + this.size + ".dex"
                var savepath = getAppDataPath()
                var path = savepath + "/" + name
                var dex_file = new File(path, "wb")
                //Memory.protect(base,4096,"rwx")
                dex_file.write(Memory.readByteArray(this.base, this.size))
                dex_file.flush();
                dex_file.close();
                console.log("OpenCommon dump over path -> ", path)
            }
        })
    }


}

function hook_DexFile_DexFile() {
    if (dexfile_dexfile_addr) {
        console.log("dexfile_dexfile_addr",dexfile_dexfile_addr)
        Interceptor.attach(dexfile_dexfile_addr, {
            onEnter: function (args) {
                this.base = ptr(args[1])//.add(Process.pointerSize * 1).readPointer();
                this.size = parseInt(args[2], 16)
                //var size = ptr(parseInt(base,16) + 0x20).readInt() // 通过dex格式来计算出size
            }, onLeave: function (retval) {
                //dex_maps[this.size] = {"base":this.base,"size":this.size};
                var name = "dexfile_dexfile_" + this.size + ".dex"
                var savepath = getAppDataPath()
                var path = savepath + "/" + name
                var dex_file = new File(path, "wb")
                //Memory.protect(base,4096,"rwx")
                dex_file.write(Memory.readByteArray(this.base, this.size))
                dex_file.flush();
                dex_file.close();
                console.log("dexfile::dexfile dump over path -> ", path)
            }
        })
    }
}

function hook_LoadMethod() {
    if (LoadMethod_addr){
        console.log("LoadMethod_addr", LoadMethod_addr)
        var dexfile_handle;
        Interceptor.attach(LoadMethod_addr,{
            onEnter:function(args){
                this.dexfileptr = args[1];

            },onLeave:function(retval){
                if (this.dexfileptr != null) {
                    var base = Memory.readPointer(ptr(this.dexfileptr).add(Process.pointerSize * 1));
                    var size = Memory.readU32(ptr(this.dexfileptr).add(Process.pointerSize * 2));
                    if (dex_maps[size] === undefined){
                        dex_maps[size] = {"base":base,"size":size};
                        console.log("Frist!" + base + "!"+ size)
                        var savepath = getAppDataPath();
                        var name = "LoadMethod_" + size + ".dex";
                        var path = savepath + "/" + name
                        dexfile_handle = new File(path, "a+");
                        if (dexfile_handle && dexfile_handle != null) {
                            var dex_buffer = ptr(base).readByteArray(size);
                            dexfile_handle.write(dex_buffer);
                            dexfile_handle.flush();
                            dexfile_handle.close();
                            console.log("LoadMethod dump over path -> ", path)
                        }
                    }else{
                        dex_maps[size] = {"base":base,"size":size};
                        //console.log("update!" + base + "!"+ size)
                    }


                }

            }
        })

    }

}
function DexFileDumpDex(){
    for (var size in dex_maps) {
        var obj = dex_maps[size];
        var base = ptr(obj["base"])
        size = parseInt(obj["size"]);
        console.log(base,size);
        var savepath = getAppDataPath();
        var name = "LastDumpDex_" + size + ".dex";
        var path = savepath + "/" + name
        var dexfile_handle = new File(path, "wb");
        if (dexfile_handle && dexfile_handle != null) {
            var dex_buffer = ptr(base).readByteArray(size);
            dexfile_handle.write(dex_buffer);
            dexfile_handle.flush();
            dexfile_handle.close();
            console.log("LoadMethod dump over path -> ", path)
        }
    }

}

function hook_Execute() {
    if (Execute_addr){
        console.log("Execute_addr", Execute_addr)
        Interceptor.attach(Execute_addr,{
            onEnter:function(args){
                console.log(args[2].GetMethod())

            },onLeave:function(retval){

            }
        })

    }

}

function main() {
    FindArtAddr()
}
setImmediate(main)