#pragma once
#include "pin.H"

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

typedef enum Opc {
  Opc_Mov,
  Opc_Not,
  Opc_Neg,
  Opc_And,
  Opc_Or,
  Opc_Xor,
  Opc_Add,
  Opc_Sub,
  Opc_Shl,
  Opc_Shr,
  Opc_Mul,
  Opc_sto,
  Opc_lod,
  Opc_end
};

typedef enum opTy{
  X86_OP_NOP,
  X86_OP_REG,
  X86_OP_MEM,
  X86_OP_IMM
};

typedef struct x86_op{
  enum opTy opTy;
  u8 sz;
  union {
    REG reg;
    u64 Imm;
    struct {
      REG Base;
      REG Idx;
      u8 sc;
      u64 dsp;
    };
  };
};

typedef struct x86Instr{
  u64 addr;
  OPCODE Opc;
  u8 op_count;
  x86_op op[4];
};

typedef struct IR{
  bool dead;
  enum Opc Opc;
  u32 dst;
  u32 lft;
  u32 rht;
};
