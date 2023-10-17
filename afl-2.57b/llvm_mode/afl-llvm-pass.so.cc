/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.
*/

#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "llvm/ADT/Statistic.h" // ADT = Advanced Data Type，llvm 为业务逻辑定义的高性能抽象类型
#include "llvm/IR/IRBuilder.h"  // IR，中间表示
#include "llvm/IR/LegacyPassManager.h" // 采用 legacy 方式编辑 pass
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;


/*
（1）匿名命名空间里的内容只能被当前代码文件调用，不能被外部引用；
（2）匿名命名空间中声明的变量和全局变量相同，声明的函数和添加了 static 关键字的函数相同。
*/
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


bool AFLCoverage::runOnModule(Module &M) {
  // 首先是获取线程上下文和声明 8 位和 32 位整型类型实例
  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  /* Show a banner */
  // 设置 AFL_QUIET 将在编译过程中不显示 afl-cc 和 afl-as 的横幅标语，以防你觉得它们令人分心。
  char be_quiet = 0;

  //isatty判断是否是文件描述符是否关联终端
  if (isatty(2) && !getenv("AFL_QUIET")) {

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

  /* Instrument all the things! */

  int inst_blocks = 0;

  for (auto &F : M)
    for (auto &BB : F) {
      // 对于module中的每一个函数的每一个base block迭代
      
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

      inst_blocks++;

    }

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%).",
             inst_blocks, getenv("AFL_HARDEN") ? "hardened" :
             ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ?
              "ASAN/MSAN" : "non-hardened"), inst_ratio);

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
    PassManagerBuilder::EP_ModuleOptimizerEarly, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
