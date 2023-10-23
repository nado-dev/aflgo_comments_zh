/**
 * This is a C++ port of ./distance.py
 *
 * Loris Reiff <loris.reiff@liblor.ch>
 */

#include <boost/program_options.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/breadth_first_search.hpp>
#include <boost/graph/graphviz.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

#include <iostream>
#include <string>
#include <unordered_map>

namespace po = boost::program_options;
namespace bo = boost;
using std::cout;
using std::cerr;
using std::exception;
using std::unordered_map;

struct Vertex {
    std::string name, label, shape;
};

struct Edge {
    std::string label;
};
typedef bo::property<bo::graph_name_t, std::string> graph_p;
typedef bo::adjacency_list<bo::vecS, bo::vecS, bo::directedS, Vertex, Edge, graph_p> graph_t;
typedef bo::graph_traits<graph_t>::vertex_descriptor vertex_desc;

static bool is_cg;

static inline std::string node_name(const std::string &name) {
    if (is_cg) {
        return "{" + name + "}";
    } else {
        return "{" + name + ":";
    }
}
/**
 * name:函数名
 * vertex_desc:节点的描述符
 * 
 * 输入节点的名称，返回这个名称在图中的节点的描述符（vertex_desc）的vector
*/
std::vector<vertex_desc> find_nodes(const graph_t &G, const std::string &name){
    std::string n_name = node_name(name); // "{" + name + "}"
    // memoization
    static unordered_map<std::string, std::vector<vertex_desc>> mem; // 使用静态的unordered_map进行缓存
    auto ver_itr = mem.find(n_name); // 检查是否已经在缓存中有对应名称的节点列表
    if (ver_itr != mem.end()) return ver_itr->second; // 如果已经缓存了相同名称的节点列表，直接返回缓存中的结果

    std::vector<vertex_desc> ret;
    bo::graph_traits<graph_t>::vertex_iterator vi, vi_end;
    for (boost::tie(vi, vi_end) = vertices(G); vi != vi_end; ++vi) { // 遍历图中的节点
    // 对每个节点检查其标签（label）是否包含目标名称
        if(G[*vi].label.find(n_name) != std::string::npos) {
            // 如果包含，将该节点描述符添加到结果向量中，vector意味着有多个匹配的结果
            ret.push_back(*vi);
        }
    }
    mem[n_name] = ret; // 加入缓存中
    return ret;
}

// for testing
vertex_desc _get_ver(const graph_t &G, const std::string &name){
    bo::graph_traits<graph_t>::vertex_iterator vi, vi_end;
    for (boost::tie(vi, vi_end) = vertices(G); vi != vi_end; ++vi) {
        if(G[*vi].name.find(name) != std::string::npos) {
            return *vi;
        }
    }
    return -1;
}
/**
 * 初始化。从图中的一个特定顶点（from）到所有其他顶点的距离，并将这些距离存储在一个名为 dists 的整数向量中。
 * 使用了 Boost Graph Library（BGL）中的相关功能
*/
inline void init_distances_from(const graph_t &G, vertex_desc from, std::vector<int> &dists) {
    auto dist_pmap = bo::make_iterator_property_map(dists.begin(), get(bo::vertex_index, G));
    auto vis = bo::make_bfs_visitor(bo::record_distances(dist_pmap, bo::on_tree_edge()));
    bo::breadth_first_search(G, from, bo::visitor(vis)); // 找到最短路径
}

void distance(
    const graph_t &G, 
    const std::string &name,
    const std::vector<vertex_desc> &targets,
    std::ofstream &out,
    unordered_map<std::string, double> &bb_distance
) {
    if (not is_cg and bb_distance.find(name) != bb_distance.end()) {
        out << name << "," << bo::lexical_cast<std::string>(10 * bb_distance[name]) << "\n";
        return; // 当计算CFG的时候才会执行这个if，先计算函数距离再计算bb距离
    }

    double distance = -1;
    for (vertex_desc n : find_nodes(G, name)) { // 输入节点的名称，返回这个名称在图中的节点的描述符（vertex_desc）的vector
        std::vector<int> distances(bo::num_vertices(G), 0);// 大小为顶点数,初始值为0的vector
        init_distances_from(G, n, distances); 
//     -->A
//       / \
//      B   C
//     / \   \
//    D   E   F  distances = [0, 1, 1, 2, 2, 2]


        double d = 0.0; // d存的是当前处理的函数到所有target函数的最短距离的调和平均数
        unsigned i = 0; // 从当前处理的函数可达的target的数量
        if (is_cg) {
            for (vertex_desc t : targets) {
                auto shortest = distances[t];           // shortest distance from n to t，当前处理的这个函数到Target之一的t的最短距离
                if (shortest == 0 and n != t) continue; // not reachable，不可达
                d += 1.0 / (1.0 + static_cast<double>(shortest)); // 论文中的调和平均数
                ++i;
            }
        } else {
            for (auto &bb_d_entry : bb_distance) {
                double di = 0.0;
                unsigned ii = 0;
                for (auto t : find_nodes(G, bb_d_entry.first)) {
                    auto shortest = distances[t];           // shortest distance from n to t，当前处理的这个函数到Target之一的t的最短距离
                    if (shortest == 0 and n != t) continue; // not reachable
                    di += 1.0 / (1.0 + 10 * bb_d_entry.second + static_cast<double>(shortest));
                    ++ii; // 可以到达目标的数量
                }
                if (ii != 0) {
                    d += di / static_cast<double>(ii);
                    ++i;
                }
            }
        }
        double tmp = static_cast<double>(i) / d; // 归一化
        if (d != 0 and (distance == -1 or distance > tmp)) {
            distance = tmp; // 要最小那个
        }
    }

    if (distance != -1) {
        // 写入文件 name,[distance( 设置为i/d )]
        out << name << "," << bo::lexical_cast<std::string>(distance) << "\n";
    }
}

/**
 * 把保存在Ftarget.txt中的Function target文本中的信息转化为对应的CG图表示中的node
 * 数据描述vertex_desc并加入到vector<vertex_desc>中
 * 
 * Ftargets中有很多个目标函数
 * 每个目标函数名对应图中一个或多个node，这些node全部加入targets
*/
std::vector<vertex_desc> cg_calculation(
    graph_t &G,
    std::ifstream &target_stream
) {
    cout << "Loading targets..\n";
    std::vector<vertex_desc> targets;
    for (std::string line; getline(target_stream, line); ) {
        bo::trim(line);
        for (auto t : find_nodes(G, line)) { // G中与line(函数名)有相同Label的节点
            targets.push_back(t);
        }
    }
    if (targets.empty()) {
        cout << "No targets available\n";
        exit(0);
    }
    return targets;
}

std::vector<vertex_desc> cfg_calculation(
    graph_t &G,
    std::ifstream &targets_stream,
    std::ifstream &cg_distance_stream, // func_name,[distance( 设置为i/d )]
    std::ifstream &cg_callsites_stream,  // BBcalls
    unordered_map<std::string, double> &cg_distance,
    unordered_map<std::string, double> &bb_distance
) {
    std::vector<vertex_desc> targets;
    for (std::string line; getline(cg_distance_stream, line); ) {
        bo::trim(line);
        std::vector<std::string> splits;
        bo::algorithm::split(splits, line, bo::is_any_of(","));;
        assert(splits.size() == 2);
        cg_distance[splits[0]] = std::stod(splits[1]); // 把cg_distance 的距离读入 map中 {function_name1, 0.11distance}, {function_name12, 0.12distance},...
    }
    if (cg_distance.empty()) {
        cerr << "Call graph distance file is empty.\n";
        exit(0);
    }

    // bbdistance 是BB中调用的某个函数 的Distance的最小值
    for (std::string line; getline(cg_callsites_stream, line); ) {
        bo::trim(line);
        std::vector<std::string> splits;
        bo::algorithm::split(splits, line, bo::is_any_of(","));; // [filename.c:123, function1], [filename.c:123, function12]
        assert(splits.size() == 2);
        if (not find_nodes(G, splits[0]).empty()) { // 如果在当前这个CFG中，找得到名字为splits[0]的BB
            if (cg_distance.find(splits[1]) != cg_distance.end()) { // 如果这个BB调用了外部函数
                if (bb_distance.find(splits[0]) != bb_distance.end()) {
                    // 把这个BB到target的距离更新为 这个BB调用的所有函数中 函数距离最小的
                    if (bb_distance[splits[0]] > cg_distance[splits[1]]) { 
                        bb_distance[splits[0]] = cg_distance[splits[1]];
                    }
                } else {
                    // 没有记录时插入记录
                    bb_distance[splits[0]] = cg_distance[splits[1]];
                }
            }
        }
    }

    // 如果某个target就在这个BB内部，那就设置为0
    cout << "Adding target BBs (if any)..\n";
    for (std::string line; getline(targets_stream, line); ) {
        bo::trim(line); //：这行代码用于去除读取的文本行中的前导和尾随空格
        std::vector<std::string> splits;
        bo::algorithm::split(splits, line, bo::is_any_of("/"));;
        size_t found = line.find_last_of('/');
        if (found != std::string::npos) // 找到
            line = line.substr(found+1);  // 如果找到了斜杠，这行代码将截取斜杠后的部分，即基本块的名称，并将其存储在 line 变量中。这是为了获取基本块的名称
        if (not find_nodes(G, splits[0]).empty()) { // B内的距离是0
            bb_distance[line] = 0.0;
            cout << "Added target BB " << line << "!\n";
        }
    }
    return targets;
}

std::ifstream open_file(const std::string &filename) {
    std::ifstream filestream(filename);
    if (not filestream) {
        cerr << "Error: " << strerror(errno) << ": " << filename << "\n";
        exit(1);
    }
    return filestream;
}

int main(int argc, char *argv[]) { 
    po::variables_map vm;
    try {
        po::options_description desc("AFLGo distance calculator Port");
        desc.add_options() // 帮助信息
                ("help,h", "produce help message")
                ("dot,d", po::value<std::string>()->required(), "Path to dot-file representing the "
                                                           "graph.")
                ("targets,t", po::value<std::string>()->required(), "Path to file specifying Target"
                                                                    " nodes.")
                ("out,o", po::value<std::string>()->required(), "Path to output file containing "
                                                                "distance for each node.")
                ("names,n", po::value<std::string>()->required(), "Path to file containing name for"
                                                                  " each node.")
                ("cg_distance,c", po::value<std::string>(), "Path to file containing call graph "
                                                            "distance.")
                ("cg_callsites,s", po::value<std::string>(), "Path to file containing mapping "
                                                             "between basic blocks and called "
                                                             "functions.")
                ;

        po::store(po::parse_command_line(argc, argv, desc), vm);
        if (vm.count("help")) {
            cout << desc << "\n";
            return 0;
        }
        po::notify(vm);
    }
    catch(exception& e) {
        cerr << "error: " << e.what() << "\n";
        return 1;
    }
    catch(...) {
        cerr << "Exception of unknown type!\n";
    }

    std::ifstream dot = open_file(vm["dot"].as<std::string>()); // 读入dot文件
    cout << "Parsing " << vm["dot"].as<std::string>() << " ..\n";
    graph_t graph(0);
    /**
     * dynamic_properties 对象是Boost.Graph库中的一个重要组件，用于在图形文件的读写中动态地处理和配置图形的属性。
     * 这允许将图的顶点、边和图本身的属性与特定的属性名称进行关联。在读取图形文件时，
     * 可以使用这些关联的属性名称来指定如何解释文件中的信息。
     * dynamic_properties 对象允许您定义和配置哪些属性应该被关联，以及如何将属性映射到图形数据结构的元素上。
     * 在图的读取过程中，它会根据配置来自动解释图形文件中的属性，并将其关联到图的顶点、边或图本身。
    */
    bo::dynamic_properties dp(bo::ignore_other_properties); // 用于存储图形属性
    dp.property("node_id", get(&Vertex::name,  graph)); // 定义属性关联，前者是dot文件中定义的属性，后者是graph中本身的属性
    dp.property("label",   get(&Vertex::label, graph));
    dp.property("shape",   get(&Vertex::shape, graph));
    dp.property("label",   get(&Edge::label,   graph));
    boost::ref_property_map<graph_t *, std::string> gname(get_property(graph, bo::graph_name));// 将图的名称属性与 graph 关联起来
    dp.property("label",    gname);
    /*
    这段代码的主要目的是准备好一个图形对象，定义各种图形属性，并将这些属性关联到图的顶点和边上。这为后续的图形解析和处理提供了必要的信息。
    通常，在读取DOT文件后，您将能够使用这些属性来操作和分析图形数据。
    */

    if (!read_graphviz(dot, graph, dp)) { // 把dot文件读入Graph内
        cerr << "Error while parsing " << vm["dot"].as<std::string>() << std::endl;
        return 1;
    }
    is_cg = get_property(graph, bo::graph_name).find("Call graph") != std::string::npos; // 如果该图是CG
    cout << "Working on " << (is_cg ? "callgraph" : "control flow graph") << "\n";

    std::ifstream targets_stream = open_file(vm["targets"].as<std::string>());
    std::ifstream names = open_file(vm["names"].as<std::string>());
    std::vector<vertex_desc> targets;
    unordered_map<std::string, double> cg_distance;
    unordered_map<std::string, double> bb_distance;

    if (is_cg) {
        targets = cg_calculation(graph, targets_stream);
    } else {
        // cfg
        if (not vm.count("cg_distance")) {
            cerr << "error: the required argument for option '--cg_distance' is missing\n";
            exit(1);
        }
        if (not vm.count("cg_callsites")) {
            cerr << "error: the required argument for option '--cg_callsites' is missing\n";
            exit(1);
        }
        std::ifstream cg_distance_stream = open_file(vm["cg_distance"].as<std::string>());
        std::ifstream cg_callsites_stream = open_file(vm["cg_callsites"].as<std::string>());

        std::vector<std::string> splits; // 用于存储分割后的字符串片段
        bo::algorithm::split(splits, vm["dot"].as<std::string>(), bo::is_any_of("."));; // .分割
        std::string &caller = splits.end()[-2]; // 提取了倒数第二个部分
        cout << "Loading cg_distance for function '" << caller << "'..\n"; // caller是某个函数的名字
        targets = cfg_calculation(graph, targets_stream, cg_distance_stream,
                                  cg_callsites_stream, cg_distance, bb_distance);
    }

    cout << "Calculating distance..\n";
    std::ofstream outstream(vm["out"].as<std::string>());
    for (std::string line; getline(names, line); ) {
        bo::trim(line);
        distance(graph, line, targets, outstream, bb_distance);
    }

    return 0;
}
