pragma circom 2.0.0;

// circom circuit.circom --r1cs --wasm --sym -o ../../build

template ArithmeticCircuit() {
    signal input c1;
    signal input c2;
    signal input c3;
    signal input c4;
    signal input c5;
    signal input c6;
    
    signal output c7;
    signal output c8;
    signal output c9;

    // Gate 1: Multiplication
    c7 <== c1 * c2;

    // Gate 2: Multiplication after Addition
    c8 <== c7 * (c3 + c4);

    // Gate 3: Multiplication after Addition
    c9 <== (c3 + c4) * (c5 + c6);
}

component main {public [c1, c2, c3, c4, c5, c6]} = ArithmeticCircuit();