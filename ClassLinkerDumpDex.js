var LoadMethod_addr;
var LinkCode_addr;
var addrGetObsoleteDexCache;

var addrGetDexFile;
var funcGetDexFile;

var savepath = "/sdcard/dexcache";
//savepath = "/data/data/com.goodl.aes.test-2"
var dex_maps = {};
var artmethod_maps = {};
var LinkCode_artmethod_maps = {};

function DexFile(start, size) {
    this.start = start;
    this.size = size;
}

function ArtMethod(dexfile, artmethodptr) {
    this.dexfile = dexfile;
    this.artmethodptr = artmethodptr;
}

function FindArtAddr() {
    var symbols = Process.getModuleByName("libart.so").enumerateSymbols();
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        if (symbol.name.indexOf("ClassLinker") >= 0
        && symbol.name.indexOf("LoadMethod") >= 0
        ) {
            LoadMethod_addr = symbol.address
        }
        if (symbol.name.indexOf("ClassLinker") >= 0
        && symbol.name.indexOf("LinkCode") >= 0
        ) {
            //console.log(JSON.stringify(symbol))
            LinkCode_addr = symbol.address
        }
        // Android >= 8
        if (symbol.name.indexOf("ArtMethod") >= 0
           && symbol.name.indexOf("GetObsoleteDexCache") >= 0
        ) {
            addrGetObsoleteDexCache = symbol.address;
        }
    }
    //hook_LoadMethod();
    hook_LinkCode();
}

function init() {
    console.log("go into init," + "Process.arch:" + Process.arch);
    var module_libext = null;
    if (Process.arch === "arm64") {
        module_libext = Module.load("/data/app/fart64.so");
    } else if (Process.arch === "arm") {
        module_libext = Module.load("/data/app/fart.so");
    }
    if (module_libext != null) {
        addrGetDexFile = module_libext.findExportByName("GetDexFile");
        funcGetDexFile = new NativeFunction(addrGetDexFile, "pointer", ["pointer", "pointer"]);
    }
}

function hook_LoadMethod() {
    if (LoadMethod_addr){
        console.log("LoadMethod_addr", LoadMethod_addr)
        Interceptor.attach(LoadMethod_addr,{
            onEnter:function(args){
                if (parseFloat(Java.androidVersion) >= 8){
                    this.dexfileptr = args[1];
                    this.artmethodptr = args[4];
                }else{
                    this.dexfileptr = args[2];
                    this.artmethodptr = args[5];
                }
            },onLeave:function(retval){
                if (this.dexfileptr != null) {
                    var dexfilebegin = Memory.readPointer(ptr(this.dexfileptr).add(Process.pointerSize * 1));
                    var dexfilesize = Memory.readU32(ptr(this.dexfileptr).add(Process.pointerSize * 2));
                    var dexfile_path = savepath + "/" + "LoadMethod_" + dexfilesize + ".dex";
                    var dexfile_handle = null;
                    try {
                        dexfile_handle = new File(dexfile_path, "r");
                        if (dexfile_handle && dexfile_handle != null) {
                            dexfile_handle.close()
                        }

                    } catch (e) {
                        dexfile_handle = new File(dexfile_path, "a+");
                        if (dexfile_handle && dexfile_handle != null) {
                            var dex_buffer = ptr(dexfilebegin).readByteArray(dexfilesize);
                            dexfile_handle.write(dex_buffer);
                            dexfile_handle.flush();
                            dexfile_handle.close();
                            console.log("[First Dumpdex]:", dexfile_path);
                        }
                    }
                    // 缓存
                    var dexfileobj = new DexFile(dexfilebegin, dexfilesize);
                    if (dex_maps[dexfilebegin] == undefined) {
                        dex_maps[dexfilebegin] = dexfilesize;
                        console.log("got a dex:", dexfilebegin, dexfilesize);
                    }
                    if (this.artmethodptr != null) {
                        var artmethodobj = new ArtMethod(dexfileobj, this.artmethodptr);
                        if (artmethod_maps[this.artmethodptr] == undefined) {
                            artmethod_maps[this.artmethodptr] = artmethodobj;
                        }
                    }



                }

            }
        })

    }

}

// Android 8.1.0
// static void LinkCode(ClassLinker* class_linker,
// 3173                     ArtMethod* method,
// 3174                     const OatFile::OatClass* oat_class,
// 3175                     uint32_t class_def_method_index) REQUIRES_SHARED(Locks::mutator_lock_)

// Android 7.1.2
// void ClassLinker::LinkCode(ArtMethod* method, const OatFile::OatClass* oat_class,
// 2880                           uint32_t class_def_method_index) {
function hook_LinkCode(){
    if(LinkCode_addr){
        console.log("LinkCode_addr", LinkCode_addr)
        Interceptor.attach(LinkCode_addr,{
            onEnter:function (args){
                if (parseFloat(Java.androidVersion) >= 8){
                    this.artmethodptr = args[1];
                }else{
                    this.artmethodptr = args[0];
                }
            },onLeave: function (retval){
                    this.dexfileptr = funcGetDexFile(ptr(this.artmethodptr), ptr(addrGetObsoleteDexCache));
                    var dexfilebegin = Memory.readPointer(ptr(this.dexfileptr).add(Process.pointerSize * 1));
                    var dexfilesize = Memory.readU32(ptr(this.dexfileptr).add(Process.pointerSize * 2));
                    var dexfile_path = savepath + "/" + "LinkCode_" + dexfilesize + ".dex";
                    var dexfile_handle = null;
                    try {
                        dexfile_handle = new File(dexfile_path, "r");
                        if (dexfile_handle && dexfile_handle != null) {
                            dexfile_handle.close()
                        }

                    } catch (e) {
                        dexfile_handle = new File(dexfile_path, "a+");
                        if (dexfile_handle && dexfile_handle != null) {
                            var dex_buffer = ptr(dexfilebegin).readByteArray(dexfilesize);
                            dexfile_handle.write(dex_buffer);
                            dexfile_handle.flush();
                            dexfile_handle.close();
                            console.log("[First Dumpdex]:", dexfile_path);
                        }
                    }
                    var dexfileobj = new DexFile(dexfilebegin, dexfilesize);
                    if (dex_maps[dexfilebegin] == undefined) {
                        dex_maps[dexfilebegin] = dexfilesize;
                        console.log("got a dex:", dexfilebegin, dexfilesize);
                    }
                if (this.artmethodptr != null) {
                    var artmethodobj = new ArtMethod(dexfileobj, this.artmethodptr);
                    if (LinkCode_artmethod_maps[this.artmethodptr] == undefined) {
                        LinkCode_artmethod_maps[this.artmethodptr] = artmethodobj;
                    }
                }
            }
        })
    }
}

function dumpDex(artmethodobj,name){
    if(artmethodobj != null){
        var dexfileobj = artmethodobj.dexfile;
        var dexfilebegin = dexfileobj.start;
        var dexfilesize = dexfileobj.size;
        var dexfile_path = savepath + "/"+ name +"_" + dexfilesize + "_" + Process.getCurrentThreadId() + ".dex";
        var dexfile_handle = null;
        try {
            dexfile_handle = new File(dexfile_path, "r");
            if (dexfile_handle && dexfile_handle != null) {
                dexfile_handle.close()
            }

        } catch (e) {
            dexfile_handle = new File(dexfile_path, "a+");
            if (dexfile_handle && dexfile_handle != null) {
                var dex_buffer = ptr(dexfilebegin).readByteArray(dexfilesize);
                dexfile_handle.write(dex_buffer);
                dexfile_handle.flush();
                dexfile_handle.close();
                console.log("[dumpdex]:", dexfile_path);
            }
        }

    }

}


function dumpclass(classname) {
    if (Java.available) {
        Java.perform(function () {
            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    try {
                        console.log("start loadclass->", className);
                        var loadclass = loader.loadClass(className);
                        console.log("after loadclass->", loadclass);

                    } catch (e) {
                        //console.log("error", e);
                    }

                },
                onComplete: function () {
                    //console.log("find  Classloader instance over");
                }
            });
            dumpLodeMethodgo();
            dumpLinkCodego();
        });
    }
}

function dumpLodeMethodgo() {
    console.log("start dump all CodeItem.......");
    for (var artmethodptr in artmethod_maps) {
        var artmethodobj = artmethod_maps[artmethodptr];
        try {
            dumpDex(artmethodobj,"LoadMethod");
        } catch (e) {
            console.log("error", e);
        }

    }
    console.log("end dump all CodeItem.......");
}

// unfinished, need artmethod -> dexfile
function dumpLinkCodego() {
    console.log("start dump all CodeItem.......");
    for (var artmethodptr in LinkCode_artmethod_maps) {
        var artmethodobj = LinkCode_artmethod_maps[artmethodptr];
        try {
            dumpDex(artmethodobj, "LinkCode");
        } catch (e) {
            console.log("error", e);
        }

    }
    console.log("end dump all CodeItem.......");
}

function dealwithClassLoader(classloaderobj) {
    if (Java.available) {
        Java.perform(function () {
            try {
                var dexfileclass = Java.use("dalvik.system.DexFile");
                var BaseDexClassLoaderclass = Java.use("dalvik.system.BaseDexClassLoader");
                var DexPathListclass = Java.use("dalvik.system.DexPathList");
                var Elementclass = Java.use("dalvik.system.DexPathList$Element");
                //console.log(classloaderobj.getClass().toString())
                var parent = classloaderobj.getClass().getSuperclass().toString();
                if (!parent.includes("BaseDexClassLoader") && !parent.includes("PathClassLoader") && !parent.includes("DexClassLoader")){
                    console.warn("now classloader is not extend BaseDexClassLoader, classloaderobj: ", classloaderobj, "getSuperclass: ", parent,"\n");
                    return;
                }
                var basedexclassloaderobj = Java.cast(classloaderobj, BaseDexClassLoaderclass);
                var tmpobj = basedexclassloaderobj.pathList.value;
                var pathlistobj = Java.cast(tmpobj, DexPathListclass);
                var dexElementsobj = pathlistobj.dexElements.value;
                if (dexElementsobj != null) {
                    for (var i in dexElementsobj) {
                        var obj = dexElementsobj[i];
                        var elementobj = Java.cast(obj, Elementclass);
                        tmpobj = elementobj.dexFile.value;
                        var dexfileobj = Java.cast(tmpobj, dexfileclass);
                        var mcookie = dexfileobj.mCookie.value;
                        var ClassnameList = dexfileclass.getClassNameList(mcookie);
                        ClassnameList.forEach(function (className){
                            try{
                                if (className.includes("csair")){
                                    var loadclass = classloaderobj.loadClass(className);
                                    console.log("after loadclass->", loadclass);
                                }
                            }catch (e) {
                                console.warn(e)
                            }
                        })
                        // const enumeratorClassNames = dexfileobj.entries();
                        // while (enumeratorClassNames.hasMoreElements()) {
                        //     var className = enumeratorClassNames.nextElement().toString();
                        //     //console.log("start loadclass->", className);
                        //     try{
                        //         var loadclass = classloaderobj.loadClass(className);
                        //         console.log("after loadclass->", loadclass);
                        //     }catch (e) {
                        //         console.log(e)
                        //     }
                        //
                        // }

                    }
                }


            } catch (e) {
                console.warn(e)
            }

        });
    }


}

function enumerateAllClassLoaders(){
    Java.perform(function (){
        Java.enumerateClassLoaders({
            onMatch:function (loader){
                try {
                    if (!loader.toString().includes("java.lang.BootClassLoader")
                    // && loader.toString().includes("libsg")
                    ){
                        console.log("start dealwithclassloader:", loader, "\n");
                        dealwithClassLoader(loader);
                    }
                } catch (e) {
                    console.log("error", e);
                }
            },onComplete: function (){

            }
        })

    })
}

function fart(){
    enumerateAllClassLoaders()
    dumpLodeMethodgo();
    dumpLinkCodego();
}

function test(addr){
    var parseArtMethodaddr = Module.findExportByName("libzed.so","parseArtMethod");
    console.log(parseArtMethodaddr);
    var parseArtMethodFunc = new NativeFunction(parseArtMethodaddr,"pointer",["pointer","pointer","pointer"]);
    console.log(parseArtMethodFunc);
    var begin = Memory.alloc(0x100);
    var size = Memory.alloc(0x100);
    console.log(begin,size)
    parseArtMethodFunc(ptr(addr),begin,size);
    console.log(begin,size)

}
init()
FindArtAddr()

