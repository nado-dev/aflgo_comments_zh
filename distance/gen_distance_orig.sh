#!/bin/bash

# usage：$AFLGO/distance/gen_distance_orig.sh $SUBJECT/obj-aflgo $TMP_DIR xmllint
if [ $# -lt 2 ]; then
  echo "Usage: $0 <binaries-directory> <temporary-directory> [fuzzer-name]"
  echo ""
  exit 1
fi

BINARIES=$(readlink -e $1) # 解析为一个绝对路径
TMPDIR=$(readlink -e $2)
AFLGO="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../" && pwd )"
fuzzer="" # <fuzzer_name>.0.0.<some_suffix>.bc 插桩后文件字节码文件
if [ $# -eq 3 ]; then
  fuzzer=$(find $BINARIES -maxdepth 1 -name "$3.0.0.*.bc" | rev | cut -d. -f5- | rev)
  if [ $(echo "$fuzzer" | wc -l) -ne 1 ]; then
    echo "Couldn't find bytecode for fuzzer $3 in folder $BINARIES."
    exit 1
  fi
fi

SCRIPT=$0
ARGS=$@

#SANITY CHECKS
if [ -z "$BINARIES" ]; then echo "Couldn't find binaries folder ($1)."; exit 1; fi # 检测字符串是否为空
if ! [ -d "$BINARIES" ]; then echo "No directory: $BINARIES."; exit 1; fi # 检测字符串对应的路径是否为存在
if [ -z "$TMPDIR" ]; then echo "Couldn't find temporary directory ($3)."; exit 1; fi

binaries=$(find $BINARIES -maxdepth 1 -name "*.0.0.*.bc" | rev | cut -d. -f5- | rev)
if [ -z "$binaries" ]; then echo "Couldn't find any binaries in folder $BINARIES."; exit; fi

if [ -z $(which python) ] && [ -z $(which python3) ]; then echo "Please install Python"; exit 1; fi
#if python -c "import pydotplus"; then echo "Install python package: pydotplus (sudo pip install pydotplus)"; exit 1; fi
#if python -c "import pydotplus; import networkx"; then echo "Install python package: networkx (sudo pip install networkx)"; exit 1; fi

FAIL=0
STEP=1

RESUME=$(if [ -f $TMPDIR/state ]; then cat $TMPDIR/state; else echo 0; fi)

function next_step {
  echo $STEP > $TMPDIR/state
  if [ $FAIL -ne 0 ]; then # 错误数量不等于0
    tail -n30 $TMPDIR/step${STEP}.log
    echo "-- Problem in Step $STEP of generating $OUT!"
    echo "-- You can resume by executing:"
    echo "$ $SCRIPT $ARGS $TMPDIR"
    exit 1
  fi
  STEP=$((STEP + 1))
}


#-------------------------------------------------------------------------------
# Construct control flow graph and call graph
#-------------------------------------------------------------------------------
if [ $RESUME -le $STEP ]; then

  cd $TMPDIR/dot-files

  if [ -z "$fuzzer" ]; then # 如果为空，表示没有特定的"fuzzer"参数传递给脚本，因此需要为所有二进制文件构建调用图。
    for binary in $(echo "$binaries"); do

      echo "($STEP) Constructing CG for $binary.."
      prefix="$TMPDIR/dot-files/$(basename $binary)"
      # 这是一个while循环，它使用opt工具来生成调用图 CG 函数级别。循环会一直执行，直到成功生成调用图。
      while ! opt -dot-callgraph $binary.0.0.*.bc -callgraph-dot-filename-prefix $prefix >/dev/null 2> $TMPDIR/step${STEP}.log ; do
        echo -e "\e[93;1m[!]\e[0m Could not generate call graph. Repeating.."
      done

      #Remove repeated lines and rename 这一行使用awk命令去除调用图文件中的重复行，并将结果保存为以二进制文件名为前缀的新文件。
      awk '!a[$0]++' $(basename $binary).callgraph.dot > callgraph.$(basename $binary).dot
      rm $(basename $binary).callgraph.dot # 这行代码删除原始的调用图文件。
    done

    #Integrate several call graphs into one 将多个调用图文件合并成一个名为callgraph.dot的调用图文件。
    $AFLGO/distance/distance_calculator/merge_callgraphs.py -o callgraph.dot $(ls callgraph.*)
    echo "($STEP) Integrating several call graphs into one."

  else

    echo "($STEP) Constructing CG for $fuzzer.."
    prefix="$TMPDIR/dot-files/$(basename $fuzzer)"
    while ! opt -dot-callgraph $fuzzer.0.0.*.bc -callgraph-dot-filename-prefix $prefix >/dev/null 2> $TMPDIR/step${STEP}.log ; do
      echo -e "\e[93;1m[!]\e[0m Could not generate call graph. Repeating.."
    done

    #Remove repeated lines and rename
    awk '!a[$0]++' $(basename $fuzzer).callgraph.dot > callgraph.dot # 存到callgraph.dot中
    rm $(basename $fuzzer).callgraph.dot

  fi
fi
next_step

#-------------------------------------------------------------------------------
# Generate config file keeping distance information for code instrumentation
#-------------------------------------------------------------------------------
if [ $RESUME -le $STEP ]; then
  echo "($STEP) Computing distance for call graph .."

  $AFLGO/distance/distance_calculator/distance.py -d $TMPDIR/dot-files/callgraph.dot -t $TMPDIR/Ftargets.txt -n $TMPDIR/Fnames.txt -o $TMPDIR/distance.callgraph.txt > $TMPDIR/step${STEP}.log 2>&1 || FAIL=1

  if [ $(cat $TMPDIR/distance.callgraph.txt | wc -l) -eq 0 ]; then # 检查文件中的行数是否为0
    FAIL=1
    next_step
  fi

  printf "($STEP) Computing distance for control-flow graphs "
  for f in $(ls -1d $TMPDIR/dot-files/cfg.*.dot); do

    # Skip CFGs of functions we are not calling
    # 这里，它用于检查 $TMPDIR/dot-files/callgraph.dot 文件中是否包含特定的$(basename $f | cut -d. -f2)。
    if ! grep "$(basename $f | cut -d. -f2)" $TMPDIR/dot-files/callgraph.dot >/dev/null; then  
      printf "\nSkipping $f..\n"
      continue
    fi

    #Clean up duplicate lines and \" in labels (bug in Pydotplus)
    awk '!a[$0]++' $f > ${f}.smaller.dot
    mv $f $f.bigger.dot
    mv $f.smaller.dot $f
    sed -i s/\\\\\"//g $f
    sed -i 's/\[.\"]//g' $f
    sed -i 's/\(^\s*[0-9a-zA-Z_]*\):[a-zA-Z0-9]*\( -> \)/\1\2/g' $f

    #Compute distance
    printf "\nComputing distance for $f..\n"
    $AFLGO/distance/distance_calculator/distance.py -d $f -t $TMPDIR/BBtargets.txt -n $TMPDIR/BBnames.txt -s $TMPDIR/BBcalls.txt -c $TMPDIR/distance.callgraph.txt -o ${f}.distances.txt >> $TMPDIR/step${STEP}.log 2>&1 #|| FAIL=1
    if [ $? -ne 0 ]; then
      echo -e "\e[93;1m[!]\e[0m Could not calculate distance for $f."
    fi
    #if [ $FAIL -eq 1 ]; then
    #  next_step #Fail asap.
    #fi
  done
  echo ""

  cat $TMPDIR/dot-files/*.distances.txt > $TMPDIR/distance.cfg.txt

fi
next_step

# 第二次插桩
echo ""
echo "----------[DONE]----------"
echo ""
echo "Now, you may wish to compile your sources with "
echo "CC=\"$AFLGO/instrument/aflgo-clang\""
echo "CXX=\"$AFLGO/instrument/aflgo-clang++\""
echo "CFLAGS=\"\$CFLAGS -distance=$(readlink -e $TMPDIR/distance.cfg.txt)\""
echo "CXXFLAGS=\"\$CXXFLAGS -distance=$(readlink -e $TMPDIR/distance.cfg.txt)\""
echo ""
echo "--------------------------"
