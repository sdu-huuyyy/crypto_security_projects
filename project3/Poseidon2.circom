pragma circom 2.0.0;

//引入Poseidon哈希模板
include "poseidon.circom";

// ---

//子电路：用于计算单个 Poseidon2 哈希
//这个模板只负责将输入连接到 Poseidon 组件，并返回一个哈希值
template Poseidon2SingleHash() {
    //私有输入：一个哈希原像（t=3）
    signal input in_preimage[3];

    //输出：计算出的哈希值
    signal output out_hash;

    //实例化 Poseidon 组件，参数为 (t=3, d=5, n=256)
    component hasher = Poseidon(3, 5, 256);
    
    //连接输入
    for (var i = 0; i < 3; i++) {
        hasher.inputs[i] <== in_preimage[i];
    }
    
    //将计算结果连接到输出
    out_hash <== hasher.out;
}

// ---

//主电路：用于验证多组 Poseidon2 哈希
//这里我们定义一个批量验证的模板，假设要验证 2 个哈希
template BatchPoseidon2Verifier() {
    //公开输入：一个包含 2 个哈希值的数组
    signal input public_hashes[2];
    
    //私有输入：一个包含 2 组原像的二维数组
    signal input secret_preimages[2][3];
    
    //实例化 2 个 Poseidon2SingleHash 子电路
    component hasher1 = Poseidon2SingleHash();
    component hasher2 = Poseidon2SingleHash();

    //连接第一组原像和断言
    for (var i = 0; i < 3; i++) {
        hasher1.in_preimage[i] <== secret_preimages[0][i];
    }
    public_hashes[0] === hasher1.out_hash;

    //连接第二组原像和断言
    for (var i = 0; i < 3; i++) {
        hasher2.in_preimage[i] <== secret_preimages[1][i];
    }
    public_hashes[1] === hasher2.out_hash;
}

// ---

//主组件，实例化 BatchPoseidon2Verifier
//将公开输入的哈希数组传递给主组件
component main {public [public_hashes]} = BatchPoseidon2Verifier();
