#!/usr/bin/env python3

import argparse
import networkx as nx

'''
usage:python script.py -o output.dot input1.dot input2.dot

input1.dot
digraph G {
  A -> B;
  B -> C;
}

digraph G {
  C -> D;
  D -> E;
}
产物output.dot
digraph G {
  A -> B;
  B -> C;
  C -> D;
  D -> E;
}

'''

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--out', type=str, required=True, help="Path to output dot file.")
    parser.add_argument('dot', nargs='+', help="Path to input dot files.")

    args = parser.parse_args()

    G = nx.DiGraph()
    for dot in args.dot:
        G.update(nx.DiGraph(nx.drawing.nx_pydot.read_dot(dot))) # 将 dot 文件解析为有向图

    with open(args.out, 'w') as f:
        nx.drawing.nx_pydot.write_dot(G, f) # 整个合并后的有向图 G 写入到输出文件中，以 dot 格式保存


# Main function
if __name__ == '__main__':
    main()
