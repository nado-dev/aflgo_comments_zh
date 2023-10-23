/*
   aflgo - LLVM instrumentation pass

   ---------------------------------

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#define AFL_LLVM_PASS

#include "../afl-2.57b/config.h"
#include "../afl-2.57b/debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <list>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "llvm/ADT/Statistic.h" // ADT = Advanced Data Type，llvm 为业务逻辑定义的高性能抽象类型
#include "llvm/IR/IRBuilder.h"  // IR，中间表示
#include "llvm/IR/LegacyPassManager.h" // 采用 legacy 方式编辑 pass
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/CFGPrinter.h"

#if defined(LLVM34)
#include "llvm/DebugInfo.h"
#else
#include "llvm/IR/DebugInfo.h"
#endif

#if defined(LLVM34) || defined(LLVM35) || defined(LLVM36)
#define LLVM_OLD_DEBUG_API
#endif

using namespace llvm;

// llvm::cl LLVM的命令行解析库,这些命令经由clang -wllvm传给 llvm处理
cl::opt<std::string> DistanceFile(
    "distance", // -distance
    cl::desc("Distance file containing the distance of each basic block to the provided targets."),
    cl::value_desc("filename")
);

// -targets=$TMP_DIR/BBtargets.txt     e.g. mjs.c:4908
cl::opt<std::string> TargetsFile(
    "targets",
    cl::desc("Input file containing the target lines of code."),
    cl::value_desc("targets"));

cl::opt<std::string> OutDirectory(
    "outdir",
    cl::desc("Output directory where Ftargets.txt, Fnames.txt, and BBnames.txt are generated."),
    cl::value_desc("outdir"));

namespace llvm {

/**
 * 用于生成dot格式的图来表示某个Function的CFG
 * 
*/
template<>
struct DOTGraphTraits<Function*> : public DefaultDOTGraphTraits {
  DOTGraphTraits(bool isSimple=true) : DefaultDOTGraphTraits(isSimple) {}

  //这个函数用于获取图的名称，通常用于指定DOT图的标题
  static std::string getGraphName(Function *F) {  
    return "CFG for '" + F->getName().str() + "' function";
  }

  // 获取CFG中每个node显示的文本
  std::string getNodeLabel(BasicBlock *Node, Function *Graph) {
    if (!Node->getName().empty()) {
      return Node->getName().str(); // 直接使用该BB的名字
    }

    std::string Str;
    raw_string_ostream OS(Str);

    Node->printAsOperand(OS, false); // 避免node没有lable
    return OS.str();
  }
};

} // namespace llvm

namespace {

  class AFLCoverage : public ModulePass {

    public:

      static char ID;
      AFLCoverage() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;

      // StringRef getPassName() const override {
      //  return "American Fuzzy Lop Instrumentation";
      // }

  };

}

char AFLCoverage::ID = 0;

/**
 * 用于获取指令I对应的文件名和行号信息
*/
static void getDebugLoc(const Instruction *I, std::string &Filename,
                        unsigned &Line) {
#ifdef LLVM_OLD_DEBUG_API
  DebugLoc Loc = I->getDebugLoc();
  if (!Loc.isUnknown()) {
    DILocation cDILoc(Loc.getAsMDNode(M.getContext()));
    DILocation oDILoc = cDILoc.getOrigLocation();

    Line = oDILoc.getLineNumber();
    Filename = oDILoc.getFilename().str();

    if (filename.empty()) {
      Line = cDILoc.getLineNumber();
      Filename = cDILoc.getFilename().str();
    }
  }
#else
  if (DILocation *Loc = I->getDebugLoc()) {
    Line = Loc->getLine();
    Filename = Loc->getFilename().str();

    if (Filename.empty()) {
      DILocation *oDILoc = Loc->getInlinedAt();
      if (oDILoc) {
        Line = oDILoc->getLine();
        Filename = oDILoc->getFilename().str();
      }
    }
  }
#endif /* LLVM_OLD_DEBUG_API */
}

/**
 * 对一下名字开头的函数，不做处理
*/
static bool isBlacklisted(const Function *F) {
  static const SmallVector<std::string, 8> Blacklist = {
    "asan.",
    "llvm.",
    "sancov.",
    "__ubsan_handle_",
    "free",
    "malloc",
    "calloc",
    "realloc"
  };

  for (auto const &BlacklistFunc : Blacklist) {
    if (F->getName().startswith(BlacklistFunc)) {
      return true;
    }
  }

  return false;
}

bool AFLCoverage::runOnModule(Module &M) {

  bool is_aflgo = false;
  bool is_aflgo_preprocessing = false;

  // 因为要编译两次,所以这个函数也会执行两次,,第一次就是预处理,,第二次计算距离
  if (!TargetsFile.empty() && !DistanceFile.empty()) {
    FATAL("Cannot specify both '-targets' and '-distance'!");
    return false;
  }

  std::list<std::string> targets;
  std::map<std::string, int> bb_to_dis;
  std::vector<std::string> basic_blocks;

  // 第一次指定的targets,和outdir两个文件夹
  // 第二次指定distance=distance.cfg.txt
  if (!TargetsFile.empty()) {

    if (OutDirectory.empty()) {
      FATAL("Provide output directory '-outdir <directory>'");
      return false;
    }

    std::ifstream targetsfile(TargetsFile); // 读入target files的记录
    std::string line;
    while (std::getline(targetsfile, line))
      targets.push_back(line); // e.g. mjs.c:4908
    targetsfile.close();

    /**
     * 预处理阶段
    */
    is_aflgo_preprocessing = true;

  } else if (!DistanceFile.empty()) {  
    /**
     * Distance file containing the distance of each basic block to the provided targets，
     * 如果设置了Distance file,则可以从文件中读出
     * 
    */
    std::ifstream cf(DistanceFile);
    if (cf.is_open()) {

      std::string line;
      while (getline(cf, line)) {

        std::size_t pos = line.find(",");
        std::string bb_name = line.substr(0, pos); // 取出名字跟距离 格式: parser.c:13085,68
        int bb_dis = (int) (100.0 * atof(line.substr(pos + 1, line.length()).c_str()));

        bb_to_dis.emplace(bb_name, bb_dis);
        basic_blocks.push_back(bb_name); // 基本块名字

      }
      cf.close();

      is_aflgo = true;

    } else {
      FATAL("Unable to find %s.", DistanceFile.c_str());
      return false;
    }

  }

  /* Show a banner */
  // 设置 AFL_QUIET 将在编译过程中不显示 afl-cc 和 afl-as 的横幅标语，以防你觉得它们令人分心。
  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    if (is_aflgo || is_aflgo_preprocessing)
      SAYF(cCYA "aflgo-llvm-pass (yeah!) " cBRI VERSION cRST " (%s mode)\n",
           (is_aflgo_preprocessing ? "preprocessing" : "distance instrumentation"));
    else
      SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");


  } else be_quiet = 1;

  /* Decide instrumentation ratio */
  // 插桩率必须在 1 到 100 间
  char* inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  // 读入并检查两个Flag 
  /* Default: Not selective */
  char* is_selective_str = getenv("AFLGO_SELECTIVE");
  unsigned int is_selective = 0;

  if (is_selective_str && sscanf(is_selective_str, "%u", &is_selective) != 1)
    FATAL("Bad value of AFLGO_SELECTIVE (must be 0 or 1)");

  char* dinst_ratio_str = getenv("AFLGO_INST_RATIO");
  unsigned int dinst_ratio = 100;

  if (dinst_ratio_str) {

    if (sscanf(dinst_ratio_str, "%u", &dinst_ratio) != 1 || !dinst_ratio ||
        dinst_ratio > 100)
      FATAL("Bad value of AFLGO_INST_RATIO (must be between 1 and 100)");

  }

  /* Instrument all the things! */

  int inst_blocks = 0;

  if (is_aflgo_preprocessing) { // 如果处于第一次（预处理阶段）预处理阶段,生成CFG文件,和一些函数名称,基本块名称信息

    // 待测软件的所有的BB的名字,每一个BB的名称形如 filename.c:123:, 123代表的行数指的是一个BB内的第一个指令对应的行数。
    std::ofstream bbnames(OutDirectory + "/BBnames.txt", std::ofstream::out | std::ofstream::app);
    // 对于所有BB，记录其被内部的函数调用指令（CallInst）调用的函数的名称
    std::ofstream bbcalls(OutDirectory + "/BBcalls.txt", std::ofstream::out | std::ofstream::app); 
    // target所在的BB对应的函数名,例如xmlBufAdd
    std::ofstream fnames(OutDirectory + "/Fnames.txt", std::ofstream::out | std::ofstream::app);
    // 如果某个函数的其中某个BB命中了的某个指令与target的某个位置对应（见BBnames.txt），写入这个函数的名字
    std::ofstream ftargets(OutDirectory + "/Ftargets.txt", std::ofstream::out | std::ofstream::app);

    /* Create dot-files directory */
    std::string dotfiles(OutDirectory + "/dot-files"); // 存放CG,CFG的文件
    if (sys::fs::create_directory(dotfiles)) {
      FATAL("Could not create directory %s.", dotfiles.c_str());
    }

    for (auto &F : M) {  // 遍历module里的每一个Function

      bool has_BBs = false;
      std::string funcName = F.getName().str();

      /* Black list of function names: 
      "asan.",
      "llvm.",
      "sancov.",
      "__ubsan_handle_",
      "free",
      "malloc",
      "calloc",
    "  realloc"  */
      if (isBlacklisted(&F)) {
        continue; 
      }

      bool is_target = false;
      for (auto &BB : F) { // 遍历Function中的每一个BB

        std::string bb_name("");
        std::string filename;
        unsigned line;

        // //这个循环是处理一个BB里面的每一行,然后写入BBname.txt,和BBcalls.txt,BBcall包含bbname和调用函数
        for (auto &I : BB) {  // 遍历Function中的每一条指令
          getDebugLoc(&I, filename, line); // 获取指令I对应的文件名和行号信息

          /* Don't worry about external libs */
          static const std::string Xlibs("/usr/");
          if (filename.empty() || line == 0 || !filename.compare(0, Xlibs.size(), Xlibs))
            continue;

          std::size_t found = filename.find_last_of("/\\");
          if (found != std::string::npos)
            filename = filename.substr(found + 1); // 从文件路径名的最后一个/后裁剪得到文件名 如main.c

          if (bb_name.empty()) // 只会设置一次，就是在第一条指令时
            bb_name = filename + ":" + std::to_string(line); //  bbname 类似于main.c:10
          
          if (!is_target) {
            for (auto &target : targets) {
              std::size_t found = target.find_last_of("/\\");
              if (found != std::string::npos)
                target = target.substr(found + 1);

              std::size_t pos = target.find_last_of(":");
              std::string target_file = target.substr(0, pos);
              unsigned int target_line = atoi(target.substr(pos + 1).c_str());

              if (!target_file.compare(filename) && target_line == line)
                is_target = true;  // 用来比较找到的BB是否是是目标块，是的话就把is_target = true

            }
          }

          if (auto *c = dyn_cast<CallInst>(&I)) {  // 如果这个指令是函数调用指令（CallInst）

            std::size_t found = filename.find_last_of("/\\");
            if (found != std::string::npos)
              filename = filename.substr(found + 1);

            if (auto *CalledF = c->getCalledFunction()) { // 对IR解码获得被该指令调用的函数的名称
              if (!isBlacklisted(CalledF))
                bbcalls << bb_name << "," << CalledF->getName().str() << "\n";  // 写入BBcalls文件,格式类似:buf.c:1013,xmlBufAdd
            }
          }
        }

        //如果bb_name有值,就设置个bb名,然后写入文件,将has_BBs置为true;
        if (!bb_name.empty()) {

          BB.setName(bb_name + ":");  // 如example.c:80:
          if (!BB.hasName()) {
            std::string newname = bb_name + ":";
            Twine t(newname);
            SmallString<256> NameData;
            StringRef NameRef = t.toStringRef(NameData);
            MallocAllocator Allocator;
            BB.setValueName(ValueName::Create(NameRef, Allocator));
          }

          bbnames << BB.getName().str() << "\n";
          has_BBs = true;

#ifdef AFLGO_TRACING
          // 基本块的终结位置插入或获取一个函数调用，该函数名为 "llvm_profiling_call（定义在runtime）"，传递 bb_name 字符串的地址作为参数。
          auto *TI = BB.getTerminator(); // 获得终结指令（Terminator），通常是分支或跳转指令，用于控制基本块的流程。
          IRBuilder<> Builder(TI);

          Value *bbnameVal = Builder.CreateGlobalStringPtr(bb_name); 
          Type *Args[] = {
              Type::getInt8PtrTy(M.getContext()) //uint8_t* bb_name
          };
          FunctionType *FTy = FunctionType::get(Type::getVoidTy(M.getContext()), Args, false); // 构建函数签名 参数分别是:返回值类型,参数
          Constant *instrumented = M.getOrInsertFunction("llvm_profiling_call", FTy); // 将构建出的函数插入module中, 外部API为instrumented，内部名称为llvm_profiling_call
          Builder.CreateCall(instrumented, {bbnameVal}); // 创建调用llvm_profiling_call(bbnameVal)

#endif

        }
      }

      if (has_BBs) {
        /* Print CFG */
        std::string cfgFileName = dotfiles + "/cfg." + funcName + ".dot";
        std::error_code EC;
        raw_fd_ostream cfgFile(cfgFileName, EC, sys::fs::F_None);
        if (!EC) {
          WriteGraph(cfgFile, &F, true); // 写入图文件
        }

        if (is_target)
          ftargets << F.getName().str() << "\n"; // 写入函数名
        fnames << F.getName().str() << "\n"; // 函数名
      }
    }

  } else {
    /* Distance instrumentation  距离插桩阶段*/

    LLVMContext &C = M.getContext(); // 获取LLVMContext,获取进程上下文
    IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
    IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

#ifdef __x86_64__
    IntegerType *LargestType = Int64Ty;
    ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 8);
#else
    IntegerType *LargestType = Int32Ty;
    ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 4);
#endif
    ConstantInt *MapDistLoc = ConstantInt::get(LargestType, MAP_SIZE);
    ConstantInt *One = ConstantInt::get(LargestType, 1);

    /* Get globals for the SHM region and the previous location. Note that
       __afl_prev_loc is thread-local. */
  // 定义两个全局变量，AFLMapPtr 和 AFLPrevLoc。
  // 前者是指向共享内存的指针，后者记录前一个基本块（已右移一位）的编号。

  /**
  这一行代码创建了一个名为 AFLMapPtr 的全局变量。
  类型是 PointerType::get(Int8Ty, 0)，这表示它是一个指向8位整数类型的指针，第二个参数0表示不指向具体的地址空间。
  false 表示它不是常量。
  GlobalValue::ExternalLinkage 表示这个全局变量可以在不同的编译单元（模块）之间共享，即它是一个外部可见的全局变量。
  0 是初始值。
  "__afl_area_ptr" 是全局变量的名称。
  */
    GlobalVariable *AFLMapPtr =
        new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

    GlobalVariable *AFLPrevLoc = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
        0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

    for (auto &F : M) {

      int distance = -1; // 距离计算使用distance中的Python脚本计算

      for (auto &BB : F) {

        distance = -1;

        if (is_aflgo) {  // 如果处在距离插桩阶段

          std::string bb_name;
          for (auto &I : BB) {
            std::string filename;
            unsigned line;
            getDebugLoc(&I, filename, line);

            if (filename.empty() || line == 0)
              continue;
            std::size_t found = filename.find_last_of("/\\");
            if (found != std::string::npos)
              filename = filename.substr(found + 1);

            bb_name = filename + ":" + std::to_string(line);
            break; // 找到BB中任意一个指令即可
          }

          // 拿到到当前bb的距离,,因为同属于一个基本块的距离都是0,所以取谁都一样,,而且前面写入也是从找到的第一个
          if (!bb_name.empty()) {
            // std::vector<std::string> basic_blocks;
            if (find(basic_blocks.begin(), basic_blocks.end(), bb_name) == basic_blocks.end()) { // 判断IR里面的基本块是否在距离文件中，找不到

              if (is_selective)
                continue;

            } else {

              /* Find distance for BB */

              if (AFL_R(100) < dinst_ratio) {
                std::map<std::string,int>::iterator it;
                for (it = bb_to_dis.begin(); it != bb_to_dis.end(); ++it)
                  if (it->first.compare(bb_name) == 0)
                    distance = it->second; // 从map中读出distance

              }
            }
          }
        }

      // 先获取其第一条指令的迭代器，这里是该BB的第一个插入点(Insert Point)，要么在 BasicBlock 的末尾，要么在块中的特定迭代器位置
        BasicBlock::iterator IP = BB.getFirstInsertionPt();
      
      // 然后使用迭代器创建一个 IRBuilder 的实例，通过该实例就可以方便地创建 IR 指令（create IR instructions），
      // 并将这些指令插在迭代器所在位置。
        IRBuilder<> IRB(&(*IP));

        if (AFL_R(100) >= inst_ratio) continue;

        /* Make up cur_loc */
      // 生成当前基本块编号 # define AFL_R(x) (random() % (x))# define AFL_R(x) (random() % (x))
      // 随机数，[0, 2^16)
        unsigned int cur_loc = AFL_R(MAP_SIZE);

        ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

        /* Load prev_loc */
      // 加载前一个基本块的编号
        LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
        PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      // 通过 CreateZExt() 完成相应的类型转换 32位整型
        Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

        /* Load SHM pointer */

        LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
        MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      // 用于创建GEP（Get Element Pointer）指令
      // 这个指令可在内存中访问数据结构的特定元素，如数组或结构体的成员
      
      // CreateXor() 对当前 BB 编号值和前驱 BB 编号值做异或，
      // 得到一个 异或结果在共享内存中的地址 的指针 MapPtrIdx，表示的是这两个BB的边
     
        Value *MapPtrIdx =
            IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

        /* Update bitmap */
      // bitmap 就是以一个 bit 位作为 key，key 对应的 value 是基本块间的边覆盖情况（如该边的命中次数）。
        LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1)); // bitmap中的命中次数+1
        IRB.CreateStore(Incr, MapPtrIdx)
           ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        /* Set prev_loc to cur_loc >> 1 */
      // 当前基本块右移一位，作为下一次计算的前驱基本块，基本块计数器自增 1。
        StoreInst *Store =
            IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
        Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        if (distance >= 0) { // 有距离就将距离插桩到共享内存中

          ConstantInt *Distance =
              ConstantInt::get(LargestType, (unsigned) distance); // 将一个整数值（distance）转化为LLVM中的常数值。

          /* Add distance to shm[MAPSIZE] 总的距离大小之和？8个字节用来存储距离和*/

          // IRB.CreateGEP创建了一个指向 MapPtr 指令的指针，该指令使用 MapDistLoc(MAP_SIZE) 作为索引
          // 通过 IRB.CreateBitCast 将上述指针转化为类型为 LargestType 的指针。
          Value *MapDistPtr = IRB.CreateBitCast(
              IRB.CreateGEP(MapPtr, MapDistLoc), LargestType->getPointerTo()); 
          LoadInst *MapDist = IRB.CreateLoad(MapDistPtr); // 从 MapDistPtr 指向的内存位置中加载一个值，并将结果存储在 MapDist 中
          MapDist->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          Value *IncrDist = IRB.CreateAdd(MapDist, Distance); // 这一行代码创建了一个加法指令，将 MapDist 和 Distance 相加，结果存储在 IncrDist 中
          IRB.CreateStore(IncrDist, MapDistPtr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None)); // 这行代码创建了一个存储指令，将 IncrDist 中的值存储到 MapDistPtr 指向的内存位置中，并设置了相应的元数据。
 
          /* Increase count at shm[MAPSIZE + (4 or 8)] 有距离的bb的数量 8个字节用来存储执行的基本块数目*/

          Value *MapCntPtr = IRB.CreateBitCast( 
              IRB.CreateGEP(MapPtr, MapCntLoc), LargestType->getPointerTo());
          LoadInst *MapCnt = IRB.CreateLoad(MapCntPtr);
          MapCnt->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          Value *IncrCnt = IRB.CreateAdd(MapCnt, One);
          IRB.CreateStore(IncrCnt, MapCntPtr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        }

        inst_blocks++;

      }
    }
  }

  /* Say something nice. */

  if (!is_aflgo_preprocessing && !be_quiet) {

    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%, dist. ratio %u%%).",
             inst_blocks,
             getenv("AFL_HARDEN")
             ? "hardened"
             : ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN"))
               ? "ASAN/MSAN" : "non-hardened"),
             inst_ratio, dinst_ratio);

  }

  return true;

}


// 注册该pass
static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}


/*
static RegisterStandardPasses AnyName(PassManagerBuilder::EP_EarlyAsPossible,
  [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
    PM.add(new Hello());
  });
*/
static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
