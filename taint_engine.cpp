#include <intrin.h>
#include "Resonance.hpp"
namespace Windows {
  #include <windows.h>
}

#define Msk1 1
#define Msk2 0b11
#define Msk4 0b1111
#define Msk8 0b11111111
#define Msk(sz) Msk##sz

#define CF(e) (e & 1)
#define PF(e) (e & 4)
#define ZF(e) (e & 0x40)
#define SF(e) (e & 0x80)
#define OF(e) (e & 0x800)

#define CB(e) CF(e)
#define CBE(e) (CF(e) | ZF(e))
#define CL(e) (SF(e) | OF(e))
#define CLE(e) (ZF(e) | SF(e) | OF(e))
#define CNB(e) CF(e)
#define CNBE(e) (CF(e) | ZF(e))
#define CNL(e) (SF(e) | OF(e))
#define CNLE(e) (ZF(e) | SF(e) | OF(e))
#define CNO(e) OF(e)
#define CNP(e) PF(e)
#define CNS(e) SF(e)
#define CNZ(e) ZF(e)
#define CO(e) OF(e)
#define CP(e) PF(e)
#define CS(e) SF(e)
#define CZ(e) ZF(e)

u8* VM_REG[4096] = {0};
u16 VM_FLG[4096] = {0};
u8* VM_MEM;

u8 taint_read(u8* Base, u64 off, u8 Len){
  u64 byte = off >> 3, bit = off & 7;
  u16 e = *(u16*)&Base[byte];
  return (e >> bit) & ((1 << Len) - 1);
}

void taint_write(u8* Base, u64 off, u8 Len, u8 data){
  u64 byte = off >> 3, bit = off & 7;
  u16* p = (u16*)&Base[byte];
  u16 Mask = ((1 << Len) - 1) << bit;
  u16 e = (u16)data << bit;
  *p = (*p & ~Mask) | (e & Mask);
}

#define VAR_REG u8 OP
#define VAR_MEM u64 OP,u8 BOP,u8 IOP
#define VAR_REGREG u8 LFT,u8 RHT
#define VAR_REGMEM u8 LFT,u64 RHT,u8 BRHT,u8 IRHT
#define VAR_MEMREG u64 LFT,u8 RHT,u8 BLFT,u8 ILFT
#define VAR_REGIMM u8 LFT
#define VAR_MEMIMM u64 LFT,u8 BLFT,u8 ILFT

#define REG_read(op,sz) taint_read(VM_REG[Tid],op,sz)
#define MEM_read(op,sz) taint_read(VM_MEM,op,sz)
#define IMM_read(op,sz) 0
#define op_read(opTy,op,sz) opTy##_read(op,sz)

#define REG_write1(op,sz,v) taint_write(VM_REG[Tid],op,1,v)
#define REG_write2(op,sz,v) taint_write(VM_REG[Tid],op,2,v)
#define REG_write4(op,sz,v) taint_write(VM_REG[Tid],op,8,v)
#define REG_write8(op,sz,v) taint_write(VM_REG[Tid],op,8,v)
#define REG_write(op,sz,v)  REG_write##sz(op,sz,v)
#define MEM_write(op,sz,v)  taint_write(VM_MEM,op,sz,v)
#define FLG_write(T,V) VM_FLG[Tid] = (VM_FLG[Tid] & (~V)) | ((T) ? V : 0)

// MOVZX qword ptr [rsp],eax 如果rsp被污染,dword ptr [rsp + 4]用污染的base清零,污染
#define READ_SIB_REG(sz,Nop) Mask = 0
#define READ_SIB_MEM(sz,Nop) bop = VM_REG[Tid][BOP >> 3],iop = VM_REG[Tid][IOP >> 3],Mask = (bop|iop) ? Msk(sz) : 0
#define READ_SIB_REGREG(lftsz,rhtsz)  Mask = 0
#define READ_SIB_REGMEM(lftsz,rhtsz)  brht = VM_REG[Tid][BRHT >> 3],irht = VM_REG[Tid][IRHT >> 3],Mask = (brht|irht) ? Msk(rhtsz) : 0
#define READ_SIB_MEMREG(lftsz,rhtsz)  blft = VM_REG[Tid][BLFT >> 3],ilft = VM_REG[Tid][ILFT >> 3],Mask = (blft|ilft) ? Msk(lftsz) : 0
#define READ_SIB_REGIMM(lftsz,rhtsz)  Mask = 0
#define READ_SIB_MEMIMM(lftsz,rhtsz)  blft = VM_REG[Tid][BLFT >> 3],ilft = VM_REG[Tid][ILFT >> 3],Mask = (blft|ilft) ? Msk(lftsz) : 0

#define TAINT_DCLR_UNA(opc,op,sz)                   void TAINT_##opc##_##op##sz(u32 Tid, CONTEXT* ctxt, x86Instr* x86, VAR_##op)
#define TAINT_READ_UNA(opTy,sz)                     u8 op = op_read(opTy,OP,sz), READ_SIB_##opTy(sz,sz)
#define TAINT_DCLR(opc,lftTy,rhtTy,sz,...)          void TAINT_##opc##_##lftTy##rhtTy##sz(u32 Tid, CONTEXT* ctxt, x86Instr* x86, VAR_##lftTy##rhtTy, __VA_ARGS__)
#define TAINT_DCLR_EXT(opc,lftTy,rhtTy,lftsz,rhtsz) void TAINT_##opc##_##lftTy##rhtTy##lftsz##rhtsz(u32 Tid, CONTEXT* ctxt, x86Instr* x86, VAR_##lftTy##rhtTy)
#define TAINT_READ_MOV(lftTy,rhtTy,lftsz,rhtsz)     u8 lft = 0, rht = op_read(rhtTy,RHT,rhtsz), READ_SIB_##lftTy##rhtTy(lftsz,rhtsz)
#define TAINT_READ(lftTy,rhtTy,sz)                  u8 lft = op_read(lftTy,LFT,sz), rht = op_read(rhtTy,RHT,sz), READ_SIB_##lftTy##rhtTy(sz,sz)

void LOG_X86(CONTEXT* ctxt, x86Instr* x86, ...);

#define Mop  OP
#define Mlft LFT
#define Mrht RHT

#define __REG(X) X
#define __MEM(X) X,b##X,i##X,M##X
#define __IMM(X) 0
#define LOG_UNA(opTy) LOG_X86(ctxt,x86,__##opTy(op))
#define LOG_BIN(lftTy,rhtTy,...) LOG_X86(ctxt,x86,__##lftTy(lft),__##rhtTy(rht),__VA_ARGS__)

#define TAINT_RULE_UNA(opTy,sz) \
TAINT_DCLR_UNA(UNA,opTy,sz){ \
  TAINT_READ_UNA(opTy,sz); \
  opTy##_write(OP,sz,op|Mask); \
  if (op|Mask) LOG_UNA(opTy); \
}

#define TAINT_RULE_UNF(opTy,sz) \
TAINT_DCLR_UNA(UNF,opTy,sz){ \
  TAINT_READ_UNA(opTy,sz); \
  opTy##_write(OP,sz,op|Mask); \
  FLG_write(op|Mask,0x8d5); \
  if (op|Mask) LOG_UNA(opTy); \
}

#define TAINT_RULE_MOV(lftTy,rhtTy,sz) \
TAINT_DCLR(MOV,lftTy,rhtTy,sz){ \
  TAINT_READ_MOV(lftTy,rhtTy,sz,sz); \
  lftTy##_write(LFT,sz,rht|Mask); \
  if (rht|Mask) LOG_BIN(lftTy,rhtTy); \
}

#define TAINT_RULE_UNI(lftTy,rhtTy,sz) \
TAINT_DCLR(UNI,lftTy,rhtTy,sz){ \
  TAINT_READ(lftTy,rhtTy,sz); \
  lftTy##_write(LFT,sz,lft|rht|Mask); \
  VM_FLG[Tid] = 0; FLG_write(lft|rht|Mask,0xc4); \
  if (lft|rht|Mask) LOG_BIN(lftTy,rhtTy); \
}

#define TAINT_RULE_TST(lftTy,rhtTy,sz) \
TAINT_DCLR(TST,lftTy,rhtTy,sz){ \
  TAINT_READ(lftTy,rhtTy,sz); \
  FLG_write(lft|rht|Mask,0x8d5); \
  if (lft|rht|Mask) LOG_BIN(lftTy,rhtTy); \
}

#define TAINT_RULE_SFT(lftTy,rhtTy,sz) \
TAINT_DCLR(SFT,lftTy,rhtTy,sz){ \
  TAINT_READ(lftTy,rhtTy,sz); \
  lftTy##_write(LFT,sz,((lft|rht) ? Msk(sz) : 0)|Mask); \
  FLG_write(lft|rht|Mask,0x801); \
  if (lft|rht|Mask) LOG_BIN(lftTy,rhtTy); \
}

#define TAINT_RULE_ARI(lftTy,rhtTy,sz) \
TAINT_DCLR(ARI,lftTy,rhtTy,sz){ \
  TAINT_READ(lftTy,rhtTy,sz); \
  lftTy##_write(LFT,sz,(lft|rht|Mask) ? Msk(sz) : 0); \
  FLG_write(lft|rht|Mask,0x8d5); \
  if (lft|rht|Mask) LOG_BIN(lftTy,rhtTy); \
}

#define TAINT_RULE_ARC(lftTy,rhtTy,sz) \
TAINT_DCLR(ARC,lftTy,rhtTy,sz){ \
  TAINT_READ(lftTy,rhtTy,sz); u16 efl = VM_FLG[Tid]; \
  lftTy##_write(LFT,sz,(lft|rht|(efl & 1)|Mask) ? Msk(sz) : 0); \
  FLG_write(lft|rht|(efl & 1)|Mask,0x8d5); \
  if (lft|rht|(efl & 1)|Mask) LOG_BIN(lftTy,rhtTy,efl); \
}

#define TAINT_RULE_XCHG(lftTy,rhtTy,sz) \
TAINT_DCLR(XCHG,lftTy,rhtTy,sz){ \
  TAINT_READ(lftTy,rhtTy,sz); \
  lftTy##_write(LFT,sz,rht|Mask); \
  rhtTy##_write(RHT,sz,lft|Mask); \
  if (lft|rht|Mask) LOG_BIN(lftTy,rhtTy); \
}

#define TAINT_RULE_XADD(lftTy,rhtTy,sz) \
TAINT_DCLR(XADD,lftTy,rhtTy,sz){ \
  TAINT_READ(lftTy,rhtTy,sz); \
  lftTy##_write(LFT,sz,((lft|rht) ? Msk(sz) : 0)|Mask); \
  rhtTy##_write(RHT,sz,lft|Mask); \
  FLG_write(lft|rht|Mask,0x8d5); \
  if (lft|rht|Mask) LOG_BIN(lftTy,rhtTy); \
}

#define TAINT_RULE_J(X) \
void TAINT_J##X(u32 Tid){ \
  u16 efl = VM_FLG[Tid]; \
  bool T = C##X(efl) ? Msk(1) : 0; \
  if (T) __LOG("J%s\n", #X); \
}

#define TAINT_RULE_SET(X,opTy,sz) \
TAINT_DCLR_UNA(SET##X,opTy,sz){ \
  TAINT_READ_UNA(opTy,sz); \
  u16 efl = VM_FLG[Tid]; \
  bool T = C##X(efl) ? Msk(1) : 0; \
  opTy##_write(OP,sz,T); \
  if (T|Mask) LOG_UNA(opTy,efl); \
}

#define TAINT_RULE_CMOV(X,lftTy,rhtTy,sz) \
TAINT_DCLR(CMOV##X,lftTy,rhtTy,sz,bool exec){ \
  TAINT_READ(lftTy,rhtTy,sz); \
  u16 efl = VM_FLG[Tid]; \
  u8 T = C##X(efl) ? Msk(sz) : (!exec) ? lft : rht; \
  lftTy##_write(LFT,sz,T|Mask); \
  if (T|Mask) LOG_BIN(lftTy,rhtTy,efl); \
}

#define TAINT_RULE_BT(lftTy,rhtTy,sz) \
TAINT_DCLR(BT,lftTy,rhtTy,sz){ \
  TAINT_READ(lftTy,rhtTy,sz); \
  lftTy##_write(LFT,sz,lft|(rht ? Msk(sz) : 0)|Mask); \
  FLG_write(lft|rht|Mask,0x1); \
  if (lft|rht|Mask) LOG_BIN(lftTy,rhtTy); \
}

#define TAINT_RULE_ZEXT(lftTy,rhtTy,lftsz,rhtsz) \
TAINT_DCLR_EXT(ZEXT,lftTy,rhtTy,lftsz,rhtsz){ \
  TAINT_READ_MOV(lftTy,rhtTy,lftsz,rhtsz); \
  lftTy##_write(LFT,lftsz,(rht|Mask)); \
  if (rht|Mask) LOG_BIN(lftTy,rhtTy); \
}

#define TAINT_RULE_SEXT(lftTy,rhtTy,lftsz,rhtsz) \
TAINT_DCLR_EXT(SEXT,lftTy,rhtTy,lftsz,rhtsz){ \
  TAINT_READ_MOV(lftTy,rhtTy,lftsz,rhtsz); \
  u8 v = (rht >> (rhtsz - 1)) ? Msk(rhtsz) << rhtsz : 0; \
  lftTy##_write(LFT,lftsz,rht|v|Mask); \
  if (rht|Mask) LOG_BIN(lftTy,rhtTy); \
}

#define TAINT_MUL1(X,Y,sz) \
void TAINT_MUL1_##sz(u32 Tid, CONTEXT* ctxt, x86Instr* x86, u8 RHT){ \
  u8 lft = taint_read(VM_REG[Tid], 8, sz), \
    rht = taint_read(VM_REG[Tid], RHT, sz), \
    T = (lft|rht) ? Msk(sz) : 0; \
  taint_write(VM_REG[Tid], X, sz, T); \
  taint_write(VM_REG[Tid], Y, sz, T); \
  FLG_write(lft|rht,0x801); \
  if (lft|rht) LOG_X86(ctxt, x86, lft, 0, rht); \
}

#define TAINT_MUL2(sz) \
void TAINT_MUL2_##sz(u32 Tid, CONTEXT* ctxt, x86Instr* x86, u8 LFT, u8 RHT){ \
  u8 lft = taint_read(VM_REG[Tid], LFT, sz), rht = taint_read(VM_REG[Tid], RHT, sz); \
  taint_write(VM_REG[Tid], LFT, sz, (lft|rht) ? Msk(sz) : 0); \
  FLG_write(lft|rht,0x801); \
  if (lft|rht) LOG_X86(ctxt, x86, lft, rht); \
}

#define TAINT_MUL3(sz) \
void TAINT_MUL3_##sz(u32 Tid, CONTEXT* ctxt, x86Instr* x86, u8 LFT, u8 RHT){ \
  u8 rht = taint_read(VM_REG[Tid], RHT, sz); \
  taint_write(VM_REG[Tid], LFT, sz, RHT ? Msk(sz) : 0); \
  FLG_write(rht,0x801); \
  if (rht) LOG_X86(ctxt, x86, 0, RHT, 0); \
}

#define TAINT_DIV1(X,Y,sz) \
void TAINT_DIV1_##sz(u32 Tid, CONTEXT* ctxt, x86Instr* x86, u8 RHT){ \
  u8 x = taint_read(VM_REG[Tid], X, sz), y = taint_read(VM_REG[Tid], Y, sz), \
  rht = taint_read(VM_REG[Tid], RHT, sz), T = (x|y|rht) ? Msk(sz) : 0; \
  taint_write(VM_REG[Tid],X,sz,T); taint_write(VM_REG[Tid],Y,sz,T); \
  if (x|y|rht) LOG_X86(ctxt,x86,x,y,rht); \
}

void TAINT_LEA(u32 Tid, CONTEXT* ctxt, x86Instr* x86, u8 LFT, u8 BRHT, u8 IRHT){
  u8 brht = VM_REG[Tid][BRHT >> 3], irht = VM_REG[Tid][IRHT >> 3];
  taint_write(VM_REG[Tid], LFT, 8, (brht | irht) ? Msk(8) : 0);
  if (brht | irht) LOG_X86(ctxt, x86, 0, 0, brht, irht, 0);
}

void TAINT_SGN(u32 Tid, CONTEXT* ctxt, x86Instr* x86, u8 LFT, u8 RHT, u8 sz){
  u8 rht = taint_read(VM_REG[Tid], RHT, sz);
  taint_write(VM_REG[Tid], LFT, sz, rht & ((1 << (sz - 1)) - 1));
  if (rht) LOG_X86(ctxt, x86, 0, rht);
}

void TAINT_PUSHFQ(u32 Tid, CONTEXT* ctxt, x86Instr* x86, u64 LFT, u8 BLFT, u8 ILFT){
  u8 rht = VM_FLG[Tid] ? Msk(2) : 0,
    blft = VM_REG[Tid][BLFT >> 3], ilft = VM_REG[Tid][ILFT >> 3];
  taint_write(VM_MEM, LFT, 8, rht);
  if (rht) LOG_X86(ctxt, x86, 0, blft, ilft, LFT, rht);
}

void TAINT_POPFQ(u32 Tid, CONTEXT* ctxt, x86Instr* x86, u64 RHT, u8 BRHT, u8 IRHT){
  u8 rht = taint_read(VM_MEM, RHT, 2),
    brht = VM_REG[Tid][BRHT >> 3], irht = VM_REG[Tid][IRHT >> 3];
  VM_FLG[Tid] = rht ? 0x8c5 : 0;
  if (rht) LOG_X86(ctxt, x86, 0, rht, brht, irht, RHT);
}

void TAINT_MOV_MEMMEM8(u32 Tid, CONTEXT* ctxt, x86Instr* x86, u64 LFT, u64 RHT, u8 BLFT, u8 ILFT, u8 BRHT, u8 IRHT){
  u8 lft = 0, rht = taint_read(VM_MEM, RHT, 8), blft = taint_read(VM_REG[Tid], BLFT, 8),
    ilft = taint_read(VM_REG[Tid], ILFT, 8), brht = taint_read(VM_REG[Tid], BRHT, 8),
    irht = taint_read(VM_REG[Tid], IRHT, 8), Mask = (blft|ilft|brht|irht) ? Msk(8) : 0;
  taint_write(VM_MEM, LFT, 8, rht|Mask);
  if (rht|Mask) LOG_BIN(MEM,MEM);
}

void TAINT_JMP_REG8(u32 Tid, CONTEXT* ctxt, x86Instr* x86, u8 OP){
  u8 op = taint_read(VM_REG[Tid], OP, 8);
  if (op)
    LOG_UNA(REG);
}

void TAINT_JMP_MEM8(u32 Tid, CONTEXT* ctxt, x86Instr* x86, VAR_MEM){
  u8 op = taint_read(VM_MEM, OP, 8),
    bop = VM_REG[Tid][BOP >> 3], iop = VM_REG[Tid][IOP >> 3];
  if (op) LOG_UNA(MEM);
}

void TAINT_CALL_REG8(u32 Tid, CONTEXT* ctxt, x86Instr* x86, u8 OP, u64 CLR){
  u8 op = taint_read(VM_REG[Tid], OP, 8);
  taint_write(VM_MEM, CLR, 8, 0);
  if (op) LOG_UNA(REG);
}

void UNTAINT_CF(u32 Tid){ VM_FLG[Tid] &= ~0x1; }
void TAINT_FXSAVE(u32 Tid, u64 OP){ memcpy((void*)(&VM_MEM[OP >> 3]), (void*)(&VM_REG[Tid][136 >> 3]), 64); }
void TAINT_FXRSTOR(u32 Tid, u64 OP){
  memcpy((void*)(&VM_REG[Tid][136 >> 3]), (void*)(&VM_MEM[OP >> 3]), 64);
  taint_write(VM_REG[Tid], 136 + 5, 1, 0);
  taint_write(VM_REG[Tid], 136 + 14, 2, 0);
  taint_write(VM_REG[Tid], 136 + 32 + 10, 6, 0);
  taint_write(VM_REG[Tid], 136 + 48 + 10, 6, 0);
  taint_write(VM_REG[Tid], 136 + 64 + 10, 6, 0);
  taint_write(VM_REG[Tid], 136 + 80 + 10, 6, 0);
  taint_write(VM_REG[Tid], 136 + 96 + 10, 6, 0);
  taint_write(VM_REG[Tid], 136 + 112 + 10, 6, 0);
  taint_write(VM_REG[Tid], 136 + 128 + 10, 6, 0);
  taint_write(VM_REG[Tid], 136 + 144 + 10, 6, 0);
}

u64 get_reg_index(REG reg){
  switch (reg){
    case REG_INVALID_: return 0;
    case REG_RAX:case REG_EAX: case REG_AX:  case REG_AL:  return 8;
    case REG_RBX:case REG_EBX: case REG_BX:  case REG_BL:  return 16;
    case REG_RCX:case REG_ECX: case REG_CX:  case REG_CL:  return 24;
    case REG_RDX:case REG_EDX: case REG_DX:  case REG_DL:  return 32;
    case REG_RBP:case REG_EBP: case REG_BP:  case REG_BPL: return 40;
    case REG_RSP:case REG_ESP: case REG_SP:  case REG_SPL: return 48;
    case REG_RSI:case REG_ESI: case REG_SI:  case REG_SIL: return 56;
    case REG_RDI:case REG_EDI: case REG_DI:  case REG_DIL: return 64;
    case REG_R8: case REG_R8D: case REG_R8W: case REG_R8B: return 72;
    case REG_R9: case REG_R9D: case REG_R9W: case REG_R9B: return 80;
    case REG_R10:case REG_R10D:case REG_R10W:case REG_R10B:return 88;
    case REG_R11:case REG_R11D:case REG_R11W:case REG_R11B:return 96;
    case REG_R12:case REG_R12D:case REG_R12W:case REG_R12B:return 104;
    case REG_R13:case REG_R13D:case REG_R13W:case REG_R13B:return 112;
    case REG_R14:case REG_R14D:case REG_R14W:case REG_R14B:return 120;
    case REG_R15:case REG_R15D:case REG_R15W:case REG_R15B:return 128;
    case REG_AH: return 8  + 1; case REG_BH: return 16 + 1;
    case REG_CH: return 24 + 1; case REG_DH: return 32 + 1;
  }
}

void MovStackDesc(INS I, x86_op* lft, x86_op* rht){
  if (INS_OperandIsReg(I, 0)){
    lft->opTy = X86_OP_REG;
    lft->sz = 8;
    lft->reg = INS_OperandReg(I, 0);
  } else if (INS_OperandIsMemory(I, 0)){
    lft->opTy = X86_OP_MEM;
    lft->sz = 8;
    lft->Base = INS_OperandMemoryBaseReg(I, 0);
    lft->Idx = INS_OperandMemoryIndexReg(I, 0);
    lft->sc = INS_OperandMemoryScale(I, 0);
    lft->dsp = INS_OperandMemoryDisplacement(I, 0);
  } else {
    lft->opTy = X86_OP_IMM;
    lft->sz = 8;
    lft->Imm = INS_OperandImmediate(I, 0);
  }
  rht->opTy = X86_OP_MEM;
  rht->sz = 8;
  rht->Base = REG_RSP;
  rht->Idx = REG_INVALID_;
  rht->sc = 0;
  rht->dsp = 0;
}

void MovFlagDesc(x86_op* lft, x86_op* rht){
  lft->opTy = X86_OP_REG;
  lft->sz = 8;
  lft->reg = REG_RFLAGS;
  rht->opTy = X86_OP_MEM;
  rht->sz = 8;
  rht->Base = REG_RSP;
  rht->Idx = REG_INVALID_;
  rht->sc = 0;
  rht->dsp = 0;
}

void MovBlockDesc(x86_op* lft, x86_op* rht, REG Base){
  lft->opTy = X86_OP_REG;
  switch (lft->sz){
    case 1: lft->reg = REG_AL;  break;
    case 2: lft->reg = REG_AX;  break;
    case 4: lft->reg = REG_EAX; break;
    case 8: lft->reg = REG_RAX; break;
  }
  rht->opTy = X86_OP_MEM;
  rht->Base = Base;
  rht->Idx = REG_INVALID_;
  rht->sc = 0;
  rht->dsp = 0;
}

x86Instr* genDesc(INS I){
  x86Instr* Instr = new x86Instr;
  Instr->addr = INS_Address(I);
  switch (INS_Opcode(I)){
  case XED_ICLASS_PUSH:
    Instr->Opc = XED_ICLASS_MOV;
    Instr->op_count = 2;
    MovStackDesc(I, &Instr->op[1], &Instr->op[0]);
    return Instr;
  case XED_ICLASS_POP:
    Instr->Opc = XED_ICLASS_MOV;
    Instr->op_count = 2;
    MovStackDesc(I, &Instr->op[0], &Instr->op[1]);
    return Instr;
  case XED_ICLASS_PUSHFQ:
    Instr->Opc = XED_ICLASS_MOV;
    Instr->op_count = 2;
    MovFlagDesc(&Instr->op[1], &Instr->op[0]);
    return Instr;
  case XED_ICLASS_POPFQ:
    Instr->Opc = XED_ICLASS_MOV;
    Instr->op_count = 2;
    MovFlagDesc(&Instr->op[0], &Instr->op[1]);
    return Instr;
  case XED_ICLASS_LODSB:
  case XED_ICLASS_LODSW:
  case XED_ICLASS_LODSD:
  case XED_ICLASS_LODSQ:
    Instr->Opc = XED_ICLASS_MOV;
    Instr->op_count = 2;
    Instr->op[0].sz = Instr->op[1].sz = INS_OperandSize(I, 0);
    MovBlockDesc(&Instr->op[0], &Instr->op[1], REG_RSI);
    return Instr;
  case XED_ICLASS_STOSB:
  case XED_ICLASS_STOSW:
  case XED_ICLASS_STOSD:
  case XED_ICLASS_STOSQ:
    Instr->Opc = XED_ICLASS_MOV;
    Instr->op_count = 2;
    Instr->op[0].sz = Instr->op[1].sz = INS_OperandSize(I, 0);
    MovBlockDesc(&Instr->op[1], &Instr->op[0], REG_RDI);
    return Instr;
  case XED_ICLASS_NOT:
  case XED_ICLASS_NEG:
  case XED_ICLASS_INC:
  case XED_ICLASS_DEC:
    Instr->op_count = 1;
    break;
  case XED_ICLASS_MUL:
  case XED_ICLASS_IMUL:
  case XED_ICLASS_DIV:
  case XED_ICLASS_IDIV:
    Instr->Opc = INS_Opcode(I);
    Instr->op_count = INS_OperandCount(I);
    if (Instr->op_count == 1){
      Instr->op[0].opTy = Instr->op[1].opTy = Instr->op[2].opTy = X86_OP_REG;
      Instr->op[0].sz = Instr->op[1].sz = Instr->op[2].sz = INS_OperandSize(I, 0);
      switch (Instr->op[0].sz){
        case 1:
          Instr->op[0].reg = REG_AL;
          Instr->op[1].reg = REG_AH;
          Instr->op[2].reg = INS_OperandReg(I, 0);
          break;
        case 2:
          Instr->op[0].reg = REG_AX;
          Instr->op[1].reg = REG_DX;
          Instr->op[2].reg = INS_OperandReg(I, 0);
          break;
        case 4:
          Instr->op[0].reg = REG_EAX;
          Instr->op[1].reg = REG_EDX;
          Instr->op[2].reg = INS_OperandReg(I, 0);
          break;
        case 8:
          Instr->op[0].reg = REG_RAX;
          Instr->op[1].reg = REG_RDX;
          Instr->op[2].reg = INS_OperandReg(I, 0);
          break;
      }
      return Instr;
    }
    break;
  case XED_ICLASS_JMP:
  case XED_ICLASS_CALL_NEAR:
    Instr->op_count = 1;
    break;
  case XED_ICLASS_RET_NEAR:
    Instr->Opc = XED_ICLASS_JMP;
    Instr->op_count = 1;
    Instr->op[0].opTy = X86_OP_MEM;
    Instr->op[0].Base = REG_RSP;
    Instr->op[0].Idx = REG_INVALID_;
    Instr->op[0].sc = 0;
    Instr->op[0].dsp = 0;
    return Instr;
  default:
    Instr->op_count = 2;
    break;
  }

  Instr->Opc = INS_Opcode(I);
  for (u8 i = 0; i < Instr->op_count; i++) {
    if (INS_OperandIsReg(I, i)){
      Instr->op[i].opTy = X86_OP_REG;
      Instr->op[i].sz = INS_OperandSize(I, i);
      Instr->op[i].reg = INS_OperandReg(I, i);
    } else if (INS_OperandIsMemory(I, i) || INS_OperandIsAddressGenerator(I, i)){
      Instr->op[i].opTy = X86_OP_MEM;
      Instr->op[i].sz = INS_OperandSize(I, i);
      Instr->op[i].Base = INS_OperandMemoryBaseReg(I, i);
      Instr->op[i].Idx = INS_OperandMemoryIndexReg(I, i);
      Instr->op[i].sc = INS_OperandMemoryScale(I, i);
      Instr->op[i].dsp = INS_OperandMemoryDisplacement(I, i);
    } else {
      Instr->op[i].opTy = X86_OP_IMM;
      Instr->op[i].sz = INS_OperandSize(I, i);
      Instr->op[i].Imm = INS_OperandImmediate(I, i);
    }
  }

  return Instr;
}

void __LOG(char* fmt, ...){
  char buffer[512];
  va_list args;
  va_start(args, fmt);
  int ret = vsnprintf(buffer, sizeof(buffer), fmt, args);
  va_end(args);
  if (ret > 0)
    Windows::OutputDebugStringA(buffer);
}

void LOG_INS(OPCODE Opc, u8 op_count, ...){
  va_list args;
  va_start(args, op_count);

  __LOG("%s ", OPCODE_StringShort(Opc).c_str());
  for (u8 i = 0; i < op_count; i++){
    x86_op* op = va_arg(args, x86_op*);
    if (!op->opTy) break;
    if (i >= 1) __LOG(",");
    switch (op->opTy){
    case X86_OP_REG:
      __LOG("%s", REG_StringShort(op->reg).c_str());
      break;
    case X86_OP_MEM:
    {
      bool need_plus = false;
      __LOG("[");
      if (op->Base){
        __LOG("%s", REG_StringShort(op->Base).c_str());
        need_plus = true;
      }
      if (op->Idx) {
        if (need_plus) __LOG("+");
        if (op->sc == 1)
          __LOG("%s", REG_StringShort(op->Idx).c_str());
        else
          __LOG("%s*%d", REG_StringShort(op->Idx).c_str(), op->sc);
        need_plus = true;
      }
      if (op->dsp) {
        if (need_plus) __LOG("+");
        __LOG("0x%llx", op->dsp);
      }
      __LOG("]");
      break;
    }
    case X86_OP_IMM:
      __LOG("0x%llx", op->Imm);
      break;
    }
  }
  __LOG("\n");
  va_end(args);
}

bool IsMove(x86Instr* x86){
  switch (x86->Opc){
    case XED_ICLASS_MOV:   case XED_ICLASS_MOVZX:
    case XED_ICLASS_MOVSX: case XED_ICLASS_MOVSXD:
    case XED_ICLASS_LEA:
      return 1;
    default: return 0;
  }
}

void LOG_X86(CONTEXT* ctxt, x86Instr* x86, ...){
  PIN_LockClient();

  u8 T, B, I;
  u64 Addr;
  x86_op cst;
  va_list args;
  va_start(args, x86);
  x86_op MyOp[3];
  MyOp[0].opTy = MyOp[1].opTy = MyOp[2].opTy = X86_OP_NOP;

  for (u8 i = 0; i < x86->op_count; i++){
    x86_op* op = &x86->op[i];
    T = va_arg(args, u8);

    switch (op->opTy){
    case X86_OP_REG:
      if (T == 0){
        if (i == 0){
          MyOp[i].opTy = X86_OP_REG;
          MyOp[i].reg = op->reg;
          if (IsMove(x86) == 0){
            cst.opTy = X86_OP_IMM;
            cst.Imm = 0;
            PIN_GetContextRegval(ctxt, op->reg, (u8*)&cst.Imm);
            LOG_INS(XED_ICLASS_MOV, 2, &MyOp[i], &cst);
          }
        } else {
          MyOp[i].opTy = X86_OP_IMM;
          MyOp[i].Imm = 0;
          PIN_GetContextRegval(ctxt, op->reg, (u8*)&MyOp[i].Imm);
        }
      } else {
        MyOp[i].opTy = X86_OP_REG;
        MyOp[i].reg = op->reg;
      }
      break;
    case X86_OP_MEM:
      B = va_arg(args, u8), I = va_arg(args, u8), Addr = va_arg(args, u64);
      if (T == 0 && B == 0 && I == 0){
        if (i == 0){
          MyOp[i].opTy = X86_OP_MEM;
          MyOp[i].Base = MyOp[i].Idx = (REG)0;
          MyOp[i].sc = 0;
          MyOp[i].dsp = Addr;
          if (IsMove(x86) == 0){
            cst.opTy = X86_OP_IMM;
            cst.Imm = 0;
            PIN_SafeCopy(&cst.Imm, (void*)Addr, op->sz);
            LOG_INS(XED_ICLASS_MOV, 2, &MyOp[i], &cst);
          }
        } else {
          MyOp[i].opTy = X86_OP_IMM;
          MyOp[i].Imm = 0;
          PIN_SafeCopy(&MyOp[i].Imm, (void*)Addr, op->sz);
        }
      } else {
        MyOp[i].opTy = X86_OP_MEM;
        MyOp[i].Base = B ? op->Base : (REG)0;
        MyOp[i].dsp = B ? 0 : PIN_GetContextReg(ctxt, op->Base);
        MyOp[i].Idx = I ? op->Idx : (REG)0;
        MyOp[i].sc = I ? op->sc : 0;
        MyOp[i].dsp += I ? 0 : PIN_GetContextReg(ctxt, op->Idx)*op->sc;
        MyOp[i].dsp += op->dsp;
      }
      break;
    case X86_OP_IMM:
      MyOp[i].opTy = X86_OP_IMM;
      MyOp[i].Imm = op->Imm;
      break;
    }
  }

  u64 Msk = 0;
  switch (x86->Opc){
    case XED_ICLASS_ADC:     Msk = 0x1; break;
    case XED_ICLASS_SBB:     Msk = 0x1; break;
    case XED_ICLASS_SETB:    Msk = 0x1; break;
    case XED_ICLASS_SETBE:   Msk = 0x1; break;
    case XED_ICLASS_SETL:    Msk = 0x80 | 0x800; break;
    case XED_ICLASS_SETLE:   Msk = 0x40 | 0x80 | 0x800; break;
    case XED_ICLASS_SETNB:   Msk = 0x1; break;
    case XED_ICLASS_SETNBE:  Msk = 0x1 | 0x40; break;
    case XED_ICLASS_SETNL:   Msk = 0x80 | 0x800; break;
    case XED_ICLASS_SETNLE:  Msk = 0x40 | 0x80 | 0x800; break;
    case XED_ICLASS_SETNO:   Msk = 0x800; break;
    case XED_ICLASS_SETNP:   Msk = 0x4; break;
    case XED_ICLASS_SETNS:   Msk = 0x80; break;
    case XED_ICLASS_SETNZ:   Msk = 0x40; break;
    case XED_ICLASS_SETO:    Msk = 0x800; break;
    case XED_ICLASS_SETP:    Msk = 0x4; break;
    case XED_ICLASS_SETS:    Msk = 0x80; break;
    case XED_ICLASS_SETZ:    Msk = 0x40; break;
    case XED_ICLASS_CMOVB:   Msk = 0x1; break;
    case XED_ICLASS_CMOVBE:  Msk = 0x1; break;
    case XED_ICLASS_CMOVL:   Msk = 0x80 | 0x800; break;
    case XED_ICLASS_CMOVLE:  Msk = 0x40 | 0x80 | 0x800; break;
    case XED_ICLASS_CMOVNB:  Msk = 0x1; break;
    case XED_ICLASS_CMOVNBE: Msk = 0x1 | 0x40; break;
    case XED_ICLASS_CMOVNL:  Msk = 0x80 | 0x800; break;
    case XED_ICLASS_CMOVNLE: Msk = 0x40 | 0x80 | 0x800; break;
    case XED_ICLASS_CMOVNO:  Msk = 0x800; break;
    case XED_ICLASS_CMOVNP:  Msk = 0x4; break;
    case XED_ICLASS_CMOVNS:  Msk = 0x80; break;
    case XED_ICLASS_CMOVNZ:  Msk = 0x40; break;
    case XED_ICLASS_CMOVO:   Msk = 0x800; break;
    case XED_ICLASS_CMOVP:   Msk = 0x4; break;
    case XED_ICLASS_CMOVS:   Msk = 0x80; break;
    case XED_ICLASS_CMOVZ:   Msk = 0x40; break;
    default: goto fn_exit;
  }
  
  u64 efl = va_arg(args, u16);
  u64 val = PIN_GetContextReg(ctxt, REG_RFLAGS);
  if ((Msk & 1) && !(efl & 1)){
    if (val & 0x1)
      __LOG("STC\n");
    else __LOG("CLC\n");
  }
  if ((Msk & 4) && !(efl & 4)){
    if (val & 0x4)
      __LOG("STP\n");
    else __LOG("CLP\n");
  }
  if ((Msk & 0x40) && !(efl & 0x40)){
    if (val & 0x40)
      __LOG("STZ\n");
    else __LOG("CLZ\n");
  }
  if ((Msk & 0x80) && !(efl & 0x80)){
    if (val & 0x80)
      __LOG("STS\n");
    else __LOG("CLS\n");
  }
  if ((Msk & 0x800) && !(efl & 0x800)){
    if (val & 0x800)
      __LOG("STO\n");
    else __LOG("CLO\n");
  }

fn_exit:
  va_end(args);
  // __LOG("%llx ", x86->addr);
  LOG_INS(x86->Opc, x86->op_count, &MyOp[0], &MyOp[1], &MyOp[2]);
  PIN_UnlockClient();
}

#define TAINT_RULES(opc,lft,rht) \
  TAINT_RULE_##opc(lft,rht,1) TAINT_RULE_##opc(lft,rht,2) \
  TAINT_RULE_##opc(lft,rht,4) TAINT_RULE_##opc(lft,rht,8)

#define TAINT_RULES_VEC(opc,lft,rht) \
  (AFUNPTR)TAINT_##opc##_##lft##rht##1, (AFUNPTR)TAINT_##opc##_##lft##rht##2, \
  (AFUNPTR)TAINT_##opc##_##lft##rht##4, (AFUNPTR)TAINT_##opc##_##lft##rht##8

TAINT_RULE_UNA(REG,1) TAINT_RULE_UNA(REG,2) TAINT_RULE_UNA(REG,4) TAINT_RULE_UNA(REG,8)
TAINT_RULE_UNA(MEM,1) TAINT_RULE_UNA(MEM,2) TAINT_RULE_UNA(MEM,4) TAINT_RULE_UNA(MEM,8)
TAINT_RULE_UNF(REG,1) TAINT_RULE_UNF(REG,2) TAINT_RULE_UNF(REG,4) TAINT_RULE_UNF(REG,8)
TAINT_RULE_UNF(MEM,1) TAINT_RULE_UNF(MEM,2) TAINT_RULE_UNF(MEM,4) TAINT_RULE_UNF(MEM,8)

TAINT_RULES(MOV,REG,REG) TAINT_RULES(MOV,REG,MEM) TAINT_RULES(MOV,MEM,REG) TAINT_RULES(MOV,REG,IMM) TAINT_RULES(MOV,MEM,IMM)
TAINT_RULES(TST,REG,REG) TAINT_RULES(TST,REG,MEM) TAINT_RULES(TST,MEM,REG) TAINT_RULES(TST,REG,IMM) TAINT_RULES(TST,MEM,IMM)
TAINT_RULES(UNI,REG,REG) TAINT_RULES(UNI,REG,MEM) TAINT_RULES(UNI,MEM,REG) TAINT_RULES(UNI,REG,IMM) TAINT_RULES(UNI,MEM,IMM)
TAINT_RULES(ARI,REG,REG) TAINT_RULES(ARI,REG,MEM) TAINT_RULES(ARI,MEM,REG) TAINT_RULES(ARI,REG,IMM) TAINT_RULES(ARI,MEM,IMM)
TAINT_RULES(ARC,REG,REG) TAINT_RULES(ARC,REG,MEM) TAINT_RULES(ARC,MEM,REG) TAINT_RULES(ARC,REG,IMM) TAINT_RULES(ARC,MEM,IMM)
TAINT_RULES(BT ,REG,REG) TAINT_RULES(BT ,REG,MEM) TAINT_RULES(BT ,MEM,REG) TAINT_RULES(BT ,REG,IMM) TAINT_RULES(BT ,MEM,IMM)
TAINT_RULES(SFT,REG,REG) TAINT_RULES(SFT,MEM,REG) TAINT_RULES(SFT,REG,IMM) TAINT_RULES(SFT,MEM,IMM)
TAINT_RULES(XCHG,REG,REG) TAINT_RULES(XCHG,REG,MEM) TAINT_RULES(XCHG,MEM,REG)
TAINT_RULES(XADD,REG,REG) TAINT_RULES(XADD,REG,MEM) TAINT_RULES(XADD,MEM,REG)
TAINT_RULE_ZEXT(REG,REG,2,1) TAINT_RULE_ZEXT(REG,REG,4,1) TAINT_RULE_ZEXT(REG,REG,4,2)
TAINT_RULE_ZEXT(REG,MEM,2,1) TAINT_RULE_ZEXT(REG,MEM,4,1) TAINT_RULE_ZEXT(REG,MEM,4,2)
TAINT_RULE_ZEXT(MEM,REG,2,1) TAINT_RULE_ZEXT(MEM,REG,4,1) TAINT_RULE_ZEXT(MEM,REG,4,2)
TAINT_RULE_SEXT(REG,REG,2,1) TAINT_RULE_SEXT(REG,REG,4,1) TAINT_RULE_SEXT(REG,REG,4,2) TAINT_RULE_SEXT(REG,REG,8,4)
TAINT_RULE_SEXT(REG,MEM,2,1) TAINT_RULE_SEXT(REG,MEM,4,1) TAINT_RULE_SEXT(REG,MEM,4,2) TAINT_RULE_SEXT(REG,MEM,8,4)
TAINT_RULE_SEXT(MEM,REG,2,1) TAINT_RULE_SEXT(MEM,REG,4,1) TAINT_RULE_SEXT(MEM,REG,4,2) TAINT_RULE_SEXT(MEM,REG,8,4)
TAINT_MUL1(8 + 1, 8, 1) TAINT_MUL1(32,8,2) TAINT_MUL1(32,8,4) TAINT_MUL1(32,8,8)
TAINT_MUL2(1) TAINT_MUL2(2) TAINT_MUL2(4) TAINT_MUL2(8)
TAINT_MUL3(1) TAINT_MUL3(2) TAINT_MUL3(4) TAINT_MUL3(8)
TAINT_DIV1(8 + 1, 8, 1) TAINT_DIV1(32,8,2) TAINT_DIV1(32,8,4) TAINT_DIV1(32,8,8)
TAINT_RULE_J(B)  TAINT_RULE_J(BE)  TAINT_RULE_J(L)  TAINT_RULE_J(LE)
TAINT_RULE_J(NB) TAINT_RULE_J(NBE) TAINT_RULE_J(NL) TAINT_RULE_J(NLE)
TAINT_RULE_J(NO) TAINT_RULE_J(NP)  TAINT_RULE_J(NS) TAINT_RULE_J(NZ)
TAINT_RULE_J(O)  TAINT_RULE_J(P)   TAINT_RULE_J(S)  TAINT_RULE_J(Z)
TAINT_RULE_SET(B ,REG,1) TAINT_RULE_SET(BE ,REG,1) TAINT_RULE_SET(L ,REG,1) TAINT_RULE_SET(LE ,REG,1)
TAINT_RULE_SET(NB,REG,1) TAINT_RULE_SET(NBE,REG,1) TAINT_RULE_SET(NL,REG,1) TAINT_RULE_SET(NLE,REG,1)
TAINT_RULE_SET(NO,REG,1) TAINT_RULE_SET(NP ,REG,1) TAINT_RULE_SET(NS,REG,1) TAINT_RULE_SET(NZ ,REG,1)
TAINT_RULE_SET(O ,REG,1) TAINT_RULE_SET(P  ,REG,1) TAINT_RULE_SET(S ,REG,1) TAINT_RULE_SET(Z  ,REG,1)
TAINT_RULE_SET(B ,MEM,1) TAINT_RULE_SET(BE ,MEM,1) TAINT_RULE_SET(L ,MEM,1) TAINT_RULE_SET(LE ,MEM,1)
TAINT_RULE_SET(NB,MEM,1) TAINT_RULE_SET(NBE,MEM,1) TAINT_RULE_SET(NL,MEM,1) TAINT_RULE_SET(NLE,MEM,1)
TAINT_RULE_SET(NO,MEM,1) TAINT_RULE_SET(NP ,MEM,1) TAINT_RULE_SET(NS,MEM,1) TAINT_RULE_SET(NZ ,MEM,1)
TAINT_RULE_SET(O ,MEM,1) TAINT_RULE_SET(P  ,MEM,1) TAINT_RULE_SET(S ,MEM,1) TAINT_RULE_SET(Z  ,MEM,1)
TAINT_RULE_CMOV(B  ,REG,REG,2) TAINT_RULE_CMOV(B  ,REG,REG,4) TAINT_RULE_CMOV(B  ,REG,REG,8)
TAINT_RULE_CMOV(BE ,REG,REG,2) TAINT_RULE_CMOV(BE ,REG,REG,4) TAINT_RULE_CMOV(BE ,REG,REG,8)
TAINT_RULE_CMOV(L  ,REG,REG,2) TAINT_RULE_CMOV(L  ,REG,REG,4) TAINT_RULE_CMOV(L  ,REG,REG,8)
TAINT_RULE_CMOV(LE ,REG,REG,2) TAINT_RULE_CMOV(LE ,REG,REG,4) TAINT_RULE_CMOV(LE ,REG,REG,8)
TAINT_RULE_CMOV(NB ,REG,REG,2) TAINT_RULE_CMOV(NB ,REG,REG,4) TAINT_RULE_CMOV(NB ,REG,REG,8)
TAINT_RULE_CMOV(NBE,REG,REG,2) TAINT_RULE_CMOV(NBE,REG,REG,4) TAINT_RULE_CMOV(NBE,REG,REG,8)
TAINT_RULE_CMOV(NL ,REG,REG,2) TAINT_RULE_CMOV(NL ,REG,REG,4) TAINT_RULE_CMOV(NL ,REG,REG,8)
TAINT_RULE_CMOV(NLE,REG,REG,2) TAINT_RULE_CMOV(NLE,REG,REG,4) TAINT_RULE_CMOV(NLE,REG,REG,8)
TAINT_RULE_CMOV(NO ,REG,REG,2) TAINT_RULE_CMOV(NO ,REG,REG,4) TAINT_RULE_CMOV(NO ,REG,REG,8)
TAINT_RULE_CMOV(NP ,REG,REG,2) TAINT_RULE_CMOV(NP ,REG,REG,4) TAINT_RULE_CMOV(NP ,REG,REG,8)
TAINT_RULE_CMOV(NS ,REG,REG,2) TAINT_RULE_CMOV(NS ,REG,REG,4) TAINT_RULE_CMOV(NS ,REG,REG,8)
TAINT_RULE_CMOV(NZ ,REG,REG,2) TAINT_RULE_CMOV(NZ ,REG,REG,4) TAINT_RULE_CMOV(NZ ,REG,REG,8)
TAINT_RULE_CMOV(O  ,REG,REG,2) TAINT_RULE_CMOV(O  ,REG,REG,4) TAINT_RULE_CMOV(O  ,REG,REG,8)
TAINT_RULE_CMOV(P  ,REG,REG,2) TAINT_RULE_CMOV(P  ,REG,REG,4) TAINT_RULE_CMOV(P  ,REG,REG,8)
TAINT_RULE_CMOV(S  ,REG,REG,2) TAINT_RULE_CMOV(S  ,REG,REG,4) TAINT_RULE_CMOV(S  ,REG,REG,8)
TAINT_RULE_CMOV(Z  ,REG,REG,2) TAINT_RULE_CMOV(Z  ,REG,REG,4) TAINT_RULE_CMOV(Z  ,REG,REG,8)
TAINT_RULE_CMOV(B  ,REG,MEM,2) TAINT_RULE_CMOV(B  ,REG,MEM,4) TAINT_RULE_CMOV(B  ,REG,MEM,8)
TAINT_RULE_CMOV(BE ,REG,MEM,2) TAINT_RULE_CMOV(BE ,REG,MEM,4) TAINT_RULE_CMOV(BE ,REG,MEM,8)
TAINT_RULE_CMOV(L  ,REG,MEM,2) TAINT_RULE_CMOV(L  ,REG,MEM,4) TAINT_RULE_CMOV(L  ,REG,MEM,8)
TAINT_RULE_CMOV(LE ,REG,MEM,2) TAINT_RULE_CMOV(LE ,REG,MEM,4) TAINT_RULE_CMOV(LE ,REG,MEM,8)
TAINT_RULE_CMOV(NB ,REG,MEM,2) TAINT_RULE_CMOV(NB ,REG,MEM,4) TAINT_RULE_CMOV(NB ,REG,MEM,8)
TAINT_RULE_CMOV(NBE,REG,MEM,2) TAINT_RULE_CMOV(NBE,REG,MEM,4) TAINT_RULE_CMOV(NBE,REG,MEM,8)
TAINT_RULE_CMOV(NL ,REG,MEM,2) TAINT_RULE_CMOV(NL ,REG,MEM,4) TAINT_RULE_CMOV(NL ,REG,MEM,8)
TAINT_RULE_CMOV(NLE,REG,MEM,2) TAINT_RULE_CMOV(NLE,REG,MEM,4) TAINT_RULE_CMOV(NLE,REG,MEM,8)
TAINT_RULE_CMOV(NO ,REG,MEM,2) TAINT_RULE_CMOV(NO ,REG,MEM,4) TAINT_RULE_CMOV(NO ,REG,MEM,8)
TAINT_RULE_CMOV(NP ,REG,MEM,2) TAINT_RULE_CMOV(NP ,REG,MEM,4) TAINT_RULE_CMOV(NP ,REG,MEM,8)
TAINT_RULE_CMOV(NS ,REG,MEM,2) TAINT_RULE_CMOV(NS ,REG,MEM,4) TAINT_RULE_CMOV(NS ,REG,MEM,8)
TAINT_RULE_CMOV(NZ ,REG,MEM,2) TAINT_RULE_CMOV(NZ ,REG,MEM,4) TAINT_RULE_CMOV(NZ ,REG,MEM,8)
TAINT_RULE_CMOV(O  ,REG,MEM,2) TAINT_RULE_CMOV(O  ,REG,MEM,4) TAINT_RULE_CMOV(O  ,REG,MEM,8)
TAINT_RULE_CMOV(P  ,REG,MEM,2) TAINT_RULE_CMOV(P  ,REG,MEM,4) TAINT_RULE_CMOV(P  ,REG,MEM,8)
TAINT_RULE_CMOV(S  ,REG,MEM,2) TAINT_RULE_CMOV(S  ,REG,MEM,4) TAINT_RULE_CMOV(S  ,REG,MEM,8)
TAINT_RULE_CMOV(Z  ,REG,MEM,2) TAINT_RULE_CMOV(Z  ,REG,MEM,4) TAINT_RULE_CMOV(Z  ,REG,MEM,8)

AFUNPTR TAINT_UNA_VEC[8] = { (AFUNPTR)TAINT_UNA_REG1,(AFUNPTR)TAINT_UNA_REG2,(AFUNPTR)TAINT_UNA_REG4,(AFUNPTR)TAINT_UNA_REG8,
                             (AFUNPTR)TAINT_UNA_MEM1,(AFUNPTR)TAINT_UNA_MEM2,(AFUNPTR)TAINT_UNA_MEM4,(AFUNPTR)TAINT_UNA_MEM8 };
AFUNPTR TAINT_UNF_VEC[8] = { (AFUNPTR)TAINT_UNF_REG1,(AFUNPTR)TAINT_UNF_REG2,(AFUNPTR)TAINT_UNF_REG4,(AFUNPTR)TAINT_UNF_REG8,
                             (AFUNPTR)TAINT_UNF_MEM1,(AFUNPTR)TAINT_UNF_MEM2,(AFUNPTR)TAINT_UNF_MEM4,(AFUNPTR)TAINT_UNF_MEM8 };
AFUNPTR TAINT_MOV_VEC[20] = { TAINT_RULES_VEC(MOV,REG,REG),TAINT_RULES_VEC(MOV,REG,MEM),TAINT_RULES_VEC(MOV,MEM,REG),TAINT_RULES_VEC(MOV,REG,IMM),TAINT_RULES_VEC(MOV,MEM,IMM) };
AFUNPTR TAINT_TST_VEC[20] = { TAINT_RULES_VEC(TST,REG,REG),TAINT_RULES_VEC(TST,REG,MEM),TAINT_RULES_VEC(TST,MEM,REG),TAINT_RULES_VEC(TST,REG,IMM),TAINT_RULES_VEC(TST,MEM,IMM) };
AFUNPTR TAINT_UNI_VEC[20] = { TAINT_RULES_VEC(UNI,REG,REG),TAINT_RULES_VEC(UNI,REG,MEM),TAINT_RULES_VEC(UNI,MEM,REG),TAINT_RULES_VEC(UNI,REG,IMM),TAINT_RULES_VEC(UNI,MEM,IMM) };
AFUNPTR TAINT_ARI_VEC[20] = { TAINT_RULES_VEC(ARI,REG,REG),TAINT_RULES_VEC(ARI,REG,MEM),TAINT_RULES_VEC(ARI,MEM,REG),TAINT_RULES_VEC(ARI,REG,IMM),TAINT_RULES_VEC(ARI,MEM,IMM) };
AFUNPTR TAINT_ARC_VEC[20] = { TAINT_RULES_VEC(ARC,REG,REG),TAINT_RULES_VEC(ARC,REG,MEM),TAINT_RULES_VEC(ARC,MEM,REG),TAINT_RULES_VEC(ARC,REG,IMM),TAINT_RULES_VEC(ARC,MEM,IMM) };
AFUNPTR TAINT_BT_VEC[20]  = { TAINT_RULES_VEC(BT ,REG,REG),TAINT_RULES_VEC(BT ,REG,MEM),TAINT_RULES_VEC(BT ,MEM,REG),TAINT_RULES_VEC(BT ,REG,IMM),TAINT_RULES_VEC(BT ,MEM,IMM) };
AFUNPTR TAINT_SFT_VEC[20]  = { TAINT_RULES_VEC(SFT,REG,REG),   0,     0,     0,     0,   TAINT_RULES_VEC(SFT,MEM,REG),TAINT_RULES_VEC(SFT,REG,IMM),TAINT_RULES_VEC(SFT,MEM,IMM) };
AFUNPTR TAINT_XCHG_VEC[12] = { TAINT_RULES_VEC(XCHG,REG,REG),TAINT_RULES_VEC(XCHG,REG,MEM),TAINT_RULES_VEC(XCHG,MEM,REG) };
AFUNPTR TAINT_XADD_VEC[12] = { TAINT_RULES_VEC(XADD,REG,REG),TAINT_RULES_VEC(XADD,REG,MEM),TAINT_RULES_VEC(XADD,MEM,REG) };
AFUNPTR TAINT_ZEXT_VEC[12] = { (AFUNPTR)TAINT_ZEXT_REGREG21,(AFUNPTR)TAINT_ZEXT_REGREG41,(AFUNPTR)TAINT_ZEXT_REGREG42,(AFUNPTR)0,
                               (AFUNPTR)TAINT_ZEXT_REGMEM21,(AFUNPTR)TAINT_ZEXT_REGMEM41,(AFUNPTR)TAINT_ZEXT_REGMEM42,(AFUNPTR)0,
                               (AFUNPTR)TAINT_ZEXT_MEMREG21,(AFUNPTR)TAINT_ZEXT_MEMREG41,(AFUNPTR)TAINT_ZEXT_MEMREG42,(AFUNPTR)0 };
AFUNPTR TAINT_SEXT_VEC[12] = { (AFUNPTR)TAINT_SEXT_REGREG21,(AFUNPTR)TAINT_SEXT_REGREG41,(AFUNPTR)TAINT_SEXT_REGREG42,(AFUNPTR)TAINT_SEXT_REGREG84,
                               (AFUNPTR)TAINT_SEXT_REGMEM21,(AFUNPTR)TAINT_SEXT_REGMEM41,(AFUNPTR)TAINT_SEXT_REGMEM42,(AFUNPTR)TAINT_SEXT_REGMEM84,
                               (AFUNPTR)TAINT_SEXT_MEMREG21,(AFUNPTR)TAINT_SEXT_MEMREG41,(AFUNPTR)TAINT_SEXT_MEMREG42,(AFUNPTR)TAINT_SEXT_MEMREG84 };
AFUNPTR TAINT_MUL_VEC[12] = { (AFUNPTR)TAINT_MUL1_1,(AFUNPTR)TAINT_MUL1_2,(AFUNPTR)TAINT_MUL1_4,(AFUNPTR)TAINT_MUL1_8,
                              (AFUNPTR)TAINT_MUL2_1,(AFUNPTR)TAINT_MUL2_2,(AFUNPTR)TAINT_MUL2_4,(AFUNPTR)TAINT_MUL2_8,
                              (AFUNPTR)TAINT_MUL3_1,(AFUNPTR)TAINT_MUL3_2,(AFUNPTR)TAINT_MUL3_4,(AFUNPTR)TAINT_MUL3_8 };
AFUNPTR TAINT_DIV_VEC[4]  = { (AFUNPTR)TAINT_DIV1_1,(AFUNPTR)TAINT_DIV1_2,(AFUNPTR)TAINT_DIV1_4,(AFUNPTR)TAINT_DIV1_8 };
AFUNPTR TAINT_SETCC_VEC[32] = { (AFUNPTR)TAINT_SETB_REG1, (AFUNPTR)TAINT_SETB_MEM1, (AFUNPTR)TAINT_SETBE_REG1, (AFUNPTR)TAINT_SETBE_MEM1,
                                (AFUNPTR)TAINT_SETL_REG1, (AFUNPTR)TAINT_SETL_MEM1, (AFUNPTR)TAINT_SETLE_REG1, (AFUNPTR)TAINT_SETLE_MEM1,
                                (AFUNPTR)TAINT_SETNB_REG1,(AFUNPTR)TAINT_SETNB_MEM1,(AFUNPTR)TAINT_SETNBE_REG1,(AFUNPTR)TAINT_SETNBE_MEM1,
                                (AFUNPTR)TAINT_SETNL_REG1,(AFUNPTR)TAINT_SETNL_MEM1,(AFUNPTR)TAINT_SETNLE_REG1,(AFUNPTR)TAINT_SETNLE_MEM1,
                                (AFUNPTR)TAINT_SETNO_REG1,(AFUNPTR)TAINT_SETNO_MEM1,(AFUNPTR)TAINT_SETNP_REG1, (AFUNPTR)TAINT_SETNP_MEM1,
                                (AFUNPTR)TAINT_SETNS_REG1,(AFUNPTR)TAINT_SETNS_MEM1,(AFUNPTR)TAINT_SETNZ_REG1, (AFUNPTR)TAINT_SETNZ_MEM1,
                                (AFUNPTR)TAINT_SETO_REG1, (AFUNPTR)TAINT_SETO_MEM1, (AFUNPTR)TAINT_SETP_REG1,  (AFUNPTR)TAINT_SETP_MEM1,
                                (AFUNPTR)TAINT_SETS_REG1, (AFUNPTR)TAINT_SETS_MEM1, (AFUNPTR)TAINT_SETZ_REG1,  (AFUNPTR)TAINT_SETZ_MEM1 };
AFUNPTR TAINT_MOVCC_VEC[96]= { (AFUNPTR)TAINT_CMOVB_REGREG2,  (AFUNPTR)TAINT_CMOVB_REGREG4,  (AFUNPTR)TAINT_CMOVB_REGREG8,
                               (AFUNPTR)TAINT_CMOVB_REGMEM2,  (AFUNPTR)TAINT_CMOVB_REGMEM4,  (AFUNPTR)TAINT_CMOVB_REGMEM8,
                               (AFUNPTR)TAINT_CMOVNB_REGREG2, (AFUNPTR)TAINT_CMOVNB_REGREG4, (AFUNPTR)TAINT_CMOVNB_REGREG8,
                               (AFUNPTR)TAINT_CMOVNB_REGMEM2, (AFUNPTR)TAINT_CMOVNB_REGMEM4, (AFUNPTR)TAINT_CMOVNB_REGMEM8,
                               (AFUNPTR)TAINT_CMOVL_REGREG2,  (AFUNPTR)TAINT_CMOVL_REGREG4,  (AFUNPTR)TAINT_CMOVL_REGREG8,
                               (AFUNPTR)TAINT_CMOVL_REGMEM2,  (AFUNPTR)TAINT_CMOVL_REGMEM4,  (AFUNPTR)TAINT_CMOVL_REGMEM8,
                               (AFUNPTR)TAINT_CMOVLE_REGREG2, (AFUNPTR)TAINT_CMOVLE_REGREG4, (AFUNPTR)TAINT_CMOVLE_REGREG8,
                               (AFUNPTR)TAINT_CMOVLE_REGMEM2, (AFUNPTR)TAINT_CMOVLE_REGMEM4, (AFUNPTR)TAINT_CMOVLE_REGMEM8,
                               (AFUNPTR)TAINT_CMOVNB_REGREG2, (AFUNPTR)TAINT_CMOVNB_REGREG4, (AFUNPTR)TAINT_CMOVNB_REGREG8,
                               (AFUNPTR)TAINT_CMOVNB_REGMEM2, (AFUNPTR)TAINT_CMOVNB_REGMEM4, (AFUNPTR)TAINT_CMOVNB_REGMEM8,
                               (AFUNPTR)TAINT_CMOVNBE_REGREG2,(AFUNPTR)TAINT_CMOVNBE_REGREG4,(AFUNPTR)TAINT_CMOVNBE_REGREG8,
                               (AFUNPTR)TAINT_CMOVNBE_REGMEM2,(AFUNPTR)TAINT_CMOVNBE_REGMEM4,(AFUNPTR)TAINT_CMOVNBE_REGMEM8,
                               (AFUNPTR)TAINT_CMOVNL_REGREG2, (AFUNPTR)TAINT_CMOVNL_REGREG4, (AFUNPTR)TAINT_CMOVNL_REGREG8,
                               (AFUNPTR)TAINT_CMOVNL_REGMEM2, (AFUNPTR)TAINT_CMOVNL_REGMEM4, (AFUNPTR)TAINT_CMOVNL_REGMEM8,
                               (AFUNPTR)TAINT_CMOVNLE_REGREG2,(AFUNPTR)TAINT_CMOVNLE_REGREG4,(AFUNPTR)TAINT_CMOVNLE_REGREG8,
                               (AFUNPTR)TAINT_CMOVNLE_REGMEM2,(AFUNPTR)TAINT_CMOVNLE_REGMEM4,(AFUNPTR)TAINT_CMOVNLE_REGMEM8,
                               (AFUNPTR)TAINT_CMOVNO_REGREG2, (AFUNPTR)TAINT_CMOVNO_REGREG4, (AFUNPTR)TAINT_CMOVNO_REGREG8,
                               (AFUNPTR)TAINT_CMOVNO_REGMEM2, (AFUNPTR)TAINT_CMOVNO_REGMEM4, (AFUNPTR)TAINT_CMOVNO_REGMEM8,
                               (AFUNPTR)TAINT_CMOVNP_REGREG2, (AFUNPTR)TAINT_CMOVNP_REGREG4, (AFUNPTR)TAINT_CMOVNP_REGREG8,
                               (AFUNPTR)TAINT_CMOVNP_REGMEM2, (AFUNPTR)TAINT_CMOVNP_REGMEM4, (AFUNPTR)TAINT_CMOVNP_REGMEM8,
                               (AFUNPTR)TAINT_CMOVNS_REGREG2, (AFUNPTR)TAINT_CMOVNS_REGREG4, (AFUNPTR)TAINT_CMOVNS_REGREG8,
                               (AFUNPTR)TAINT_CMOVNS_REGMEM2, (AFUNPTR)TAINT_CMOVNS_REGMEM4, (AFUNPTR)TAINT_CMOVNS_REGMEM8,
                               (AFUNPTR)TAINT_CMOVNZ_REGREG2, (AFUNPTR)TAINT_CMOVNZ_REGREG4, (AFUNPTR)TAINT_CMOVNZ_REGREG8,
                               (AFUNPTR)TAINT_CMOVNZ_REGMEM2, (AFUNPTR)TAINT_CMOVNZ_REGMEM4, (AFUNPTR)TAINT_CMOVNZ_REGMEM8,
                               (AFUNPTR)TAINT_CMOVO_REGREG2,  (AFUNPTR)TAINT_CMOVO_REGREG4,  (AFUNPTR)TAINT_CMOVO_REGREG8,
                               (AFUNPTR)TAINT_CMOVO_REGMEM2,  (AFUNPTR)TAINT_CMOVO_REGMEM4,  (AFUNPTR)TAINT_CMOVO_REGMEM8,
                               (AFUNPTR)TAINT_CMOVP_REGREG2,  (AFUNPTR)TAINT_CMOVP_REGREG4,  (AFUNPTR)TAINT_CMOVP_REGREG8,
                               (AFUNPTR)TAINT_CMOVP_REGMEM2,  (AFUNPTR)TAINT_CMOVP_REGMEM4,  (AFUNPTR)TAINT_CMOVP_REGMEM8,
                               (AFUNPTR)TAINT_CMOVS_REGREG2,  (AFUNPTR)TAINT_CMOVS_REGREG4,  (AFUNPTR)TAINT_CMOVS_REGREG8,
                               (AFUNPTR)TAINT_CMOVS_REGMEM2,  (AFUNPTR)TAINT_CMOVS_REGMEM4,  (AFUNPTR)TAINT_CMOVS_REGMEM8,
                               (AFUNPTR)TAINT_CMOVZ_REGREG2,  (AFUNPTR)TAINT_CMOVZ_REGREG4,  (AFUNPTR)TAINT_CMOVZ_REGREG8,
                               (AFUNPTR)TAINT_CMOVZ_REGMEM2,  (AFUNPTR)TAINT_CMOVZ_REGMEM4,  (AFUNPTR)TAINT_CMOVZ_REGMEM8 };

#define ARG_U64(x) IARG_UINT64, (u64)x
#define ARG_REG(x) IARG_UINT64, get_reg_index(INS_OperandReg(I, x))
#define ARG_MEM_0 IARG_MEMORYWRITE_EA
#define ARG_MEM_1 IARG_MEMORYREAD_EA
#define ARG_MEM(x) ARG_MEM_##x
#define ARG_SIB(x) IARG_UINT64, get_reg_index(INS_OperandMemoryBaseReg(I, x)), IARG_UINT64, get_reg_index(INS_OperandMemoryIndexReg(I, x))
#define SetCall(fn,...) INS_InsertCall(I, IPOINT_BEFORE, (AFUNPTR)fn, IARG_THREAD_ID, \
  IARG_CONST_CONTEXT, IARG_UINT64, genDesc(I), __VA_ARGS__, IARG_END)

void SetCall_UNA(INS I, AFUNPTR* ptr){
  u8 sz = INS_OperandSize(I, 0);
  if (sz == 1) sz = 0;
  else if (sz == 2) sz = 1;
  else if (sz == 4) sz = 2;
  else if (sz == 8) sz = 3;
  if (INS_OperandIsReg(I, 0))
    SetCall(*(ptr + sz), ARG_REG(0));
  else if (INS_OperandIsMemory(I, 0))
    SetCall(*(ptr + 4 + sz), ARG_MEM(0), ARG_SIB(0));
}

void SetCall_stkop(INS I){
  if (INS_Opcode(I) == XED_ICLASS_PUSHFQ)
    SetCall(TAINT_PUSHFQ, IARG_MEMORYWRITE_EA, ARG_U64(48), ARG_U64(0));
  else if (INS_Opcode(I) == XED_ICLASS_POPFQ)
    SetCall(TAINT_POPFQ, IARG_MEMORYREAD_EA, ARG_U64(48), ARG_U64(0));
  else if (INS_OperandIsReg(I, 0)){
    if (INS_Opcode(I) == XED_ICLASS_PUSH)
      SetCall(TAINT_MOV_MEMREG8, IARG_MEMORYWRITE_EA, ARG_REG(0), ARG_U64(48), ARG_U64(0));
    else if (INS_Opcode(I) == XED_ICLASS_POP)
      SetCall(TAINT_MOV_REGMEM8, ARG_REG(0), IARG_MEMORYREAD_EA, ARG_U64(48), ARG_U64(0));
  } else if (INS_OperandIsMemory(I, 0)){
    if (INS_Opcode(I) == XED_ICLASS_PUSH)
      SetCall(TAINT_MOV_MEMMEM8, IARG_MEMORYWRITE_EA, IARG_MEMORYREAD_EA, ARG_U64(48), ARG_U64(0), ARG_SIB(0));
    else if (INS_Opcode(I) == XED_ICLASS_POP)
      SetCall(TAINT_MOV_MEMMEM8, IARG_MEMORYWRITE_EA, IARG_MEMORYREAD_EA, ARG_SIB(0), ARG_U64(48), ARG_U64(0));
  } else if (INS_OperandIsImmediate(I, 0))
    SetCall(TAINT_MOV_MEMIMM8, IARG_MEMORYWRITE_EA, ARG_U64(48), ARG_U64(0));
}

void SetCall_BIN(INS I, AFUNPTR* ptr){
  u64 sz = 0, lftsz = INS_OperandSize(I, 0),
    rhtsz = INS_OperandSize(I, 1);
  if (lftsz != rhtsz){
    if (lftsz == 2 && rhtsz == 1) sz = 0;
    else if (lftsz == 4 && rhtsz == 1) sz = 1;
    else if (lftsz == 4 && rhtsz == 2) sz = 2;
    else if (lftsz == 8 && rhtsz == 4) sz = 3;
  } else {
    if (lftsz == 1) sz = 0;
    else if (lftsz == 2) sz = 1;
    else if (lftsz == 4) sz = 2;
    else if (lftsz == 8) sz = 3;
  }

  if ((INS_Opcode(I) == XED_ICLASS_XOR) || (INS_Opcode(I) == XED_ICLASS_SUB)){
    if (INS_OperandIsReg(I, 0) && INS_OperandIsReg(I, 1)){
      if (INS_OperandReg(I, 0) == INS_OperandReg(I, 1)){
        SetCall(*(TAINT_MOV_VEC + 12 + sz), ARG_REG(0));
        return;
      }
    }
  }

  if (((INS_Opcode(I) == XED_ICLASS_CMP) || (INS_Opcode(I) == XED_ICLASS_TEST) ||
    (INS_Opcode(I) == XED_ICLASS_BT)) && INS_OperandIsMemory(I, 0)){
    SetCall(*(ptr + 8 + sz), IARG_MEMORYREAD_EA, ARG_REG(1), ARG_SIB(0));
    return;
  }

  if (INS_OperandIsReg(I, 0) && INS_OperandIsReg(I, 1))
    SetCall(*(ptr + sz), ARG_REG(0), ARG_REG(1));
  else if (INS_OperandIsReg(I, 0) && INS_OperandIsMemory(I, 1))
    SetCall(*(ptr + 4 + sz), ARG_REG(0), ARG_MEM(1), ARG_SIB(1));
  else if (INS_OperandIsMemory(I, 0) && INS_OperandIsReg(I, 1))
    SetCall(*(ptr + 8 + sz), ARG_MEM(0), ARG_REG(1), ARG_SIB(0));
  else if (INS_OperandIsReg(I, 0) && INS_OperandIsImmediate(I, 1))
    SetCall(*(ptr + 12 + sz), ARG_REG(0));
  else if (INS_OperandIsMemory(I, 0) && INS_OperandIsImmediate(I, 1))
    SetCall(*(ptr + 16 + sz), ARG_MEM(0), ARG_SIB(0));
}

void SetCall_Setcc(INS I, AFUNPTR* ptr){
  if (INS_OperandIsReg(I, 0))
    SetCall(*ptr, ARG_REG(0));
  else SetCall(*(ptr + 1), ARG_MEM(0), ARG_SIB(0));
}

void SetCall_Movcc(INS I, AFUNPTR* ptr){
  u64 sz = INS_OperandSize(I, 0);
  if (sz == 2) sz = 0;
  else if (sz == 4) sz = 1;
  else if (sz == 8) sz = 2;
  if (INS_OperandIsReg(I, 0) && INS_OperandIsReg(I, 1))
    SetCall(*(ptr + sz), ARG_REG(0), ARG_REG(1), IARG_EXECUTING);
  else if (INS_OperandIsReg(I, 0) && INS_OperandIsMemory(I, 1))
    SetCall(*(ptr + 3 + sz), ARG_REG(0), ARG_MEM(1), ARG_SIB(1), IARG_EXECUTING);
}

void SetCall_MulDiv(INS I, AFUNPTR* ptr){
  u8 sz = INS_OperandSize(I, 0);
  if (sz == 1) sz = 0;
  else if (sz == 2) sz = 1;
  else if (sz == 4) sz = 2;
  else if (sz == 8) sz = 3;

  if (INS_Opcode(I) == XED_ICLASS_DIV || INS_Opcode(I) == XED_ICLASS_IDIV)
    if (INS_OperandCount(I) != 1) __debugbreak();

  if (INS_OperandCount(I) == 1)
    SetCall(*(ptr + sz), ARG_REG(0));
  else if (INS_OperandCount(I) == 2)
    SetCall(*(ptr + 4 + sz), ARG_REG(0), ARG_REG(1));
  else if (INS_OperandCount(I) == 3)
    SetCall(*(ptr + 8 + sz), ARG_REG(0), ARG_REG(1));
}

u64 tsc = __rdtsc();
void TAINT_RDTSC(u32 Tid, CONTEXT* ctxt){
  __LOG("rdtsc\n");
  PIN_SetContextReg(ctxt, REG_RAX, tsc & 0xffffffff);
  PIN_SetContextReg(ctxt, REG_RDX, (tsc >> 32) & 0xffffffff);
  tsc += 250;
  taint_write(VM_REG[Tid], 8,  4, Msk(4));
  taint_write(VM_REG[Tid], 32, 4, Msk(4));
}

struct Region{
  ADDRINT low;
  ADDRINT high;
};

bool MainEntered = false;
std::vector<Region> excludedRegions;
void EnterMain(){ MainEntered = true; }
bool IsAddressExcluded(ADDRINT addr){
  bool Excluded = false;
  for (const auto& region : excludedRegions){
    if (addr >= region.low && addr < region.high){
      Excluded = true;
      break;
    }
  }
  return (!MainEntered) || Excluded;
}

void Instru_x86(INS I, void* v){
  if (IsAddressExcluded(INS_Address(I)))
    return;
  OPCODE opc = INS_Opcode(I);
  switch (opc){
  case XED_ICLASS_MOV:   SetCall_BIN(I, TAINT_MOV_VEC); break;
  case XED_ICLASS_MOVZX: SetCall_BIN(I, TAINT_ZEXT_VEC); break;
  case XED_ICLASS_MOVSX: case XED_ICLASS_MOVSXD: SetCall_BIN(I, TAINT_SEXT_VEC); break;
  case XED_ICLASS_LEA: SetCall(TAINT_LEA, ARG_REG(0), ARG_SIB(1)); break;
  case XED_ICLASS_PUSH: case XED_ICLASS_POP: case XED_ICLASS_PUSHFQ: case XED_ICLASS_POPFQ: SetCall_stkop(I); break;
  case XED_ICLASS_LODSB: SetCall(TAINT_MOV_REGMEM1, ARG_REG(0), ARG_MEM(1), ARG_U64(56), ARG_U64(0)); break;
  case XED_ICLASS_LODSW: SetCall(TAINT_MOV_REGMEM2, ARG_REG(0), ARG_MEM(1), ARG_U64(56), ARG_U64(0)); break;
  case XED_ICLASS_LODSD: SetCall(TAINT_MOV_REGMEM4, ARG_REG(0), ARG_MEM(1), ARG_U64(56), ARG_U64(0)); break;
  case XED_ICLASS_LODSQ: SetCall(TAINT_MOV_REGMEM8, ARG_REG(0), ARG_MEM(1), ARG_U64(56), ARG_U64(0)); break;
  case XED_ICLASS_STOSB: SetCall(TAINT_MOV_MEMREG1, ARG_MEM(0), ARG_REG(1), ARG_U64(56), ARG_U64(0)); break;
  case XED_ICLASS_STOSW: SetCall(TAINT_MOV_MEMREG2, ARG_MEM(0), ARG_REG(1), ARG_U64(56), ARG_U64(0)); break;
  case XED_ICLASS_STOSD: SetCall(TAINT_MOV_MEMREG4, ARG_MEM(0), ARG_REG(1), ARG_U64(56), ARG_U64(0)); break;
  case XED_ICLASS_STOSQ: SetCall(TAINT_MOV_MEMREG8, ARG_MEM(0), ARG_REG(1), ARG_U64(56), ARG_U64(0)); break;
  case XED_ICLASS_NOT: SetCall_UNA(I, TAINT_UNA_VEC); break;
  case XED_ICLASS_NEG: case XED_ICLASS_INC: case XED_ICLASS_DEC: SetCall_UNA(I, TAINT_UNF_VEC); break;
  case XED_ICLASS_AND: case XED_ICLASS_OR:  case XED_ICLASS_XOR: SetCall_BIN(I, TAINT_UNI_VEC); break;
  case XED_ICLASS_MUL: case XED_ICLASS_IMUL: SetCall_MulDiv(I, TAINT_MUL_VEC); break;
  case XED_ICLASS_DIV: case XED_ICLASS_IDIV: SetCall_MulDiv(I, TAINT_DIV_VEC); break;
  case XED_ICLASS_ADD: case XED_ICLASS_SUB:  SetCall_BIN(I, TAINT_ARI_VEC); break;
  case XED_ICLASS_CMP: case XED_ICLASS_TEST: SetCall_BIN(I, TAINT_TST_VEC); break;
  case XED_ICLASS_CLC: case XED_ICLASS_STC:  INS_InsertCall(I, IPOINT_BEFORE, (AFUNPTR)UNTAINT_CF, IARG_THREAD_ID, IARG_END); break;
  case XED_ICLASS_ADC: case XED_ICLASS_SBB:  SetCall_BIN(I, TAINT_ARC_VEC); return;
  case XED_ICLASS_SHL: case XED_ICLASS_SHR: case XED_ICLASS_ROL: case XED_ICLASS_ROR:
  case XED_ICLASS_RCL: case XED_ICLASS_RCR: case XED_ICLASS_SAR: SetCall_BIN(I, TAINT_SFT_VEC); break;
  case XED_ICLASS_BT:  case XED_ICLASS_BTC: case XED_ICLASS_BTR: case XED_ICLASS_BTS: SetCall_BIN(I, TAINT_BT_VEC); break;
  case XED_ICLASS_XCHG: SetCall_BIN(I, TAINT_XCHG_VEC); break;
  case XED_ICLASS_XADD: SetCall_BIN(I, TAINT_XADD_VEC); break;
  case XED_ICLASS_CBW:  SetCall(TAINT_SGN, ARG_U64(8 + 1), ARG_U64(8), ARG_U64(1)); break;
  case XED_ICLASS_CWD:  SetCall(TAINT_SGN, ARG_U64(32),    ARG_U64(8), ARG_U64(2)); break;
  case XED_ICLASS_CWDE: SetCall(TAINT_SGN, ARG_U64(8 + 2), ARG_U64(8), ARG_U64(2)); break;
  case XED_ICLASS_CDQ:  SetCall(TAINT_SGN, ARG_U64(32),    ARG_U64(8), ARG_U64(4)); break;
  case XED_ICLASS_CDQE: SetCall(TAINT_SGN, ARG_U64(8 + 4), ARG_U64(8), ARG_U64(4)); break;
  case XED_ICLASS_CQO:  SetCall(TAINT_SGN, ARG_U64(32),    ARG_U64(8), ARG_U64(8)); break;
  case XED_ICLASS_JB:   INS_InsertCall(I, IPOINT_BEFORE, (AFUNPTR)TAINT_JB,   IARG_THREAD_ID, IARG_END); break;
  case XED_ICLASS_JBE:  INS_InsertCall(I, IPOINT_BEFORE, (AFUNPTR)TAINT_JBE,  IARG_THREAD_ID, IARG_END); break;
  case XED_ICLASS_JL:   INS_InsertCall(I, IPOINT_BEFORE, (AFUNPTR)TAINT_JL,   IARG_THREAD_ID, IARG_END); break;
  case XED_ICLASS_JLE:  INS_InsertCall(I, IPOINT_BEFORE, (AFUNPTR)TAINT_JLE,  IARG_THREAD_ID, IARG_END); break;
  case XED_ICLASS_JNB:  INS_InsertCall(I, IPOINT_BEFORE, (AFUNPTR)TAINT_JNB,  IARG_THREAD_ID, IARG_END); break;
  case XED_ICLASS_JNBE: INS_InsertCall(I, IPOINT_BEFORE, (AFUNPTR)TAINT_JNBE, IARG_THREAD_ID, IARG_END); break;
  case XED_ICLASS_JNL:  INS_InsertCall(I, IPOINT_BEFORE, (AFUNPTR)TAINT_JNL,  IARG_THREAD_ID, IARG_END); break;
  case XED_ICLASS_JNLE: INS_InsertCall(I, IPOINT_BEFORE, (AFUNPTR)TAINT_JNLE, IARG_THREAD_ID, IARG_END); break;
  case XED_ICLASS_JNO:  INS_InsertCall(I, IPOINT_BEFORE, (AFUNPTR)TAINT_JNO,  IARG_THREAD_ID, IARG_END); break;
  case XED_ICLASS_JNP:  INS_InsertCall(I, IPOINT_BEFORE, (AFUNPTR)TAINT_JNP,  IARG_THREAD_ID, IARG_END); break;
  case XED_ICLASS_JNS:  INS_InsertCall(I, IPOINT_BEFORE, (AFUNPTR)TAINT_JNS,  IARG_THREAD_ID, IARG_END); break;
  case XED_ICLASS_JNZ:  INS_InsertCall(I, IPOINT_BEFORE, (AFUNPTR)TAINT_JNZ,  IARG_THREAD_ID, IARG_END); break;
  case XED_ICLASS_JO:   INS_InsertCall(I, IPOINT_BEFORE, (AFUNPTR)TAINT_JO,   IARG_THREAD_ID, IARG_END); break;
  case XED_ICLASS_JP:   INS_InsertCall(I, IPOINT_BEFORE, (AFUNPTR)TAINT_JP,   IARG_THREAD_ID, IARG_END); break;
  case XED_ICLASS_JS:   INS_InsertCall(I, IPOINT_BEFORE, (AFUNPTR)TAINT_JS,   IARG_THREAD_ID, IARG_END); break;
  case XED_ICLASS_JZ:   INS_InsertCall(I, IPOINT_BEFORE, (AFUNPTR)TAINT_JZ,   IARG_THREAD_ID, IARG_END); break;
  case XED_ICLASS_SETB:   SetCall_Setcc(I, TAINT_SETCC_VEC + 0);  break;
  case XED_ICLASS_SETBE:  SetCall_Setcc(I, TAINT_SETCC_VEC + 2);  break;
  case XED_ICLASS_SETL:   SetCall_Setcc(I, TAINT_SETCC_VEC + 4);  break;
  case XED_ICLASS_SETLE:  SetCall_Setcc(I, TAINT_SETCC_VEC + 6);  break;
  case XED_ICLASS_SETNB:  SetCall_Setcc(I, TAINT_SETCC_VEC + 8);  break;
  case XED_ICLASS_SETNBE: SetCall_Setcc(I, TAINT_SETCC_VEC + 10); break;
  case XED_ICLASS_SETNL:  SetCall_Setcc(I, TAINT_SETCC_VEC + 12); break;
  case XED_ICLASS_SETNLE: SetCall_Setcc(I, TAINT_SETCC_VEC + 14); break;
  case XED_ICLASS_SETNO:  SetCall_Setcc(I, TAINT_SETCC_VEC + 16); break;
  case XED_ICLASS_SETNP:  SetCall_Setcc(I, TAINT_SETCC_VEC + 18); break;
  case XED_ICLASS_SETNS:  SetCall_Setcc(I, TAINT_SETCC_VEC + 20); break;
  case XED_ICLASS_SETNZ:  SetCall_Setcc(I, TAINT_SETCC_VEC + 22); break;
  case XED_ICLASS_SETO:   SetCall_Setcc(I, TAINT_SETCC_VEC + 24); break;
  case XED_ICLASS_SETP:   SetCall_Setcc(I, TAINT_SETCC_VEC + 26); break;
  case XED_ICLASS_SETS:   SetCall_Setcc(I, TAINT_SETCC_VEC + 28); break;
  case XED_ICLASS_SETZ:   SetCall_Setcc(I, TAINT_SETCC_VEC + 30); break;
  case XED_ICLASS_CMOVB:  SetCall_Movcc(I, TAINT_MOVCC_VEC + 0);  break;
  case XED_ICLASS_CMOVBE: SetCall_Movcc(I, TAINT_MOVCC_VEC + 6);  break;
  case XED_ICLASS_CMOVL:  SetCall_Movcc(I, TAINT_MOVCC_VEC + 12); break;
  case XED_ICLASS_CMOVLE: SetCall_Movcc(I, TAINT_MOVCC_VEC + 18); break;
  case XED_ICLASS_CMOVNB: SetCall_Movcc(I, TAINT_MOVCC_VEC + 24); break;
  case XED_ICLASS_CMOVNBE:SetCall_Movcc(I, TAINT_MOVCC_VEC + 30); break;
  case XED_ICLASS_CMOVNL: SetCall_Movcc(I, TAINT_MOVCC_VEC + 36); break;
  case XED_ICLASS_CMOVNLE:SetCall_Movcc(I, TAINT_MOVCC_VEC + 42); break;
  case XED_ICLASS_CMOVNO: SetCall_Movcc(I, TAINT_MOVCC_VEC + 48); break;
  case XED_ICLASS_CMOVNP: SetCall_Movcc(I, TAINT_MOVCC_VEC + 54); break;
  case XED_ICLASS_CMOVNS: SetCall_Movcc(I, TAINT_MOVCC_VEC + 60); break;
  case XED_ICLASS_CMOVNZ: SetCall_Movcc(I, TAINT_MOVCC_VEC + 66); break;
  case XED_ICLASS_CMOVO:  SetCall_Movcc(I, TAINT_MOVCC_VEC + 72); break;
  case XED_ICLASS_CMOVP:  SetCall_Movcc(I, TAINT_MOVCC_VEC + 78); break;
  case XED_ICLASS_CMOVS:  SetCall_Movcc(I, TAINT_MOVCC_VEC + 84); break;
  case XED_ICLASS_CMOVZ:  SetCall_Movcc(I, TAINT_MOVCC_VEC + 90); break;
  case XED_ICLASS_CALL_NEAR: if (INS_OperandIsReg(I, 0)) SetCall(TAINT_CALL_REG8, ARG_REG(0), IARG_MEMORYWRITE_EA); break;
  case XED_ICLASS_JMP: if (INS_OperandIsReg(I, 0)) SetCall(TAINT_JMP_REG8, ARG_REG(0)); break;
  case XED_ICLASS_RET_NEAR: SetCall(TAINT_JMP_MEM8, IARG_MEMORYREAD_EA); break;
  case XED_ICLASS_FXSAVE:
    INS_InsertCall(I, IPOINT_BEFORE, (AFUNPTR)TAINT_FXSAVE, IARG_THREAD_ID, IARG_MEMORYWRITE_EA, IARG_END);
    break;
  case XED_ICLASS_FXRSTOR:
    INS_InsertCall(I, IPOINT_BEFORE, (AFUNPTR)TAINT_FXRSTOR, IARG_THREAD_ID, IARG_MEMORYREAD_EA, IARG_END);
    break;
  case XED_ICLASS_NOP:
  case XED_ICLASS_CMC:
  case XED_ICLASS_CLD:
  case XED_ICLASS_STD:
  case XED_ICLASS_SHLD:
  case XED_ICLASS_SHRD:
  case XED_ICLASS_BSWAP:
  case XED_ICLASS_SYSCALL:
    break;
  case XED_ICLASS_RDTSC:
    INS_InsertCall(I, IPOINT_BEFORE, (AFUNPTR)TAINT_RDTSC, IARG_THREAD_ID, IARG_CONTEXT, IARG_END);
    break;
  default: 
    __LOG("UnSupport Instr %llx: %s\n", INS_Address(I), INS_Disassemble(I).c_str());
    break;
  }
}

const u64 VM_MEM_SIZE = 16ULL * 1024 * 1024 * 1024 * 1024;
EXCEPT_HANDLING_RESULT MyExceptionHandler(
  THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, void* v){

  EXCEPTION_CODE excCode = PIN_GetExceptionCode(pExceptInfo);
  if (excCode == EXCEPTCODE_RECEIVED_ACCESS_FAULT){
    ADDRINT faultyAddress;
    PIN_GetFaultyAccessAddress(pExceptInfo, &faultyAddress);
    if (faultyAddress >= reinterpret_cast<ADDRINT>(VM_MEM) &&
      faultyAddress < reinterpret_cast<ADDRINT>(VM_MEM) + VM_MEM_SIZE){

      void* pageAddr = reinterpret_cast<void*>(faultyAddress & ~0xFFFULL);
      void* page = Windows::VirtualAlloc(pageAddr, 0x1000, MEM_COMMIT, PAGE_READWRITE);
      if (!page){
        Windows::MEMORY_BASIC_INFORMATION Info;
        if (VirtualQuery(pageAddr, &Info, sizeof(Info)) &&
          (Info.State == MEM_COMMIT) &&
          (Info.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))){
          return EHR_HANDLED;
        } else __debugbreak();
      }
      return EHR_HANDLED;
    }
  }

  ADDRINT exceptAddr = PIN_GetExceptionAddress(pExceptInfo);
  std::string excStr = PIN_ExceptionToString(pExceptInfo);
  __LOG("Internal Exception\nAddress: %llx\nDetails: %s\n", exceptAddr, excStr.c_str());

  return EHR_HANDLED;
}

void Engine_OnInit(void* v){
  VM_MEM = (u8*)Windows::VirtualAlloc(nullptr, VM_MEM_SIZE, MEM_RESERVE, PAGE_NOACCESS);
  if (!VM_MEM) __debugbreak();

  for (u64 i = 0; i < 4096; i += 8)
    taint_write(VM_MEM, 0x7ffe0000 + i, 8, Msk(8));

  u64 PEB = __readgsqword(0x60);
  __LOG("PEB Addr: %llx\n", PEB);
  for (u64 i = PEB; i < PEB + 2000; i += 8)
    taint_write(VM_MEM, PEB + i, 8, Msk(8));
}

void OnFunctionEntry(u32 Tid, ADDRINT RET, char* Name){
  if (IsAddressExcluded(RET))
    return;
  taint_write(VM_REG[Tid], 8, 8, Msk(1));
  __LOG("CALL FROM %llx Name: %s\n", RET, Name);
}

void Hook_SteamAPI_RestartAppIfNecessary(u32 Tid, u64* RAX){
  *RAX = 0;
  taint_write(VM_REG[Tid], 8, 8, Msk(8));
  __LOG("SteamAPI_RestartAppIfNecessary\n");
}

void IMG_OnLoad(IMG IMG, void* v){
  std::string IMG_Path = IMG_Name(IMG);
  u64 LowAddr = IMG_LowAddress(IMG);
  u64 HighAddr = IMG_HighAddress(IMG);
  RTN RTN;

  if (!IMG_IsMainExecutable(IMG)){
    excludedRegions.push_back({ LowAddr, HighAddr });
  } else {
    u64 Entry = IMG_EntryAddress(IMG);
    RTN = RTN_FindByAddress(Entry);
    if (RTN_Valid(RTN)) {
      RTN_Open(RTN);
      RTN_InsertCall(RTN, IPOINT_BEFORE, (AFUNPTR)EnterMain, IARG_END);
      RTN_Close(RTN);
    }
  }

  //if (IMG_Path.find("C:\\Windows\\") != std::string::npos)
  //  excludedRegions.push_back({ LowAddr, HighAddr });

  RTN = RTN_FindByName(IMG, "SteamAPI_RestartAppIfNecessary");
  if (RTN_Valid(RTN)){
    PROTO proto_type = PROTO_Allocate(PIN_PARG(bool), CALLINGSTD_DEFAULT, "SteamAPI_RestartAppIfNecessary", PIN_PARG(uint32_t), PIN_PARG_END());
    RTN_ReplaceSignature(RTN, (AFUNPTR)Hook_SteamAPI_RestartAppIfNecessary, IARG_PROTOTYPE, proto_type, IARG_THREAD_ID, IARG_REG_REFERENCE, REG_RAX, IARG_END);
  }

  for (SEC SEC = IMG_SecHead(IMG); SEC_Valid(SEC); SEC = SEC_Next(SEC)){
    for (RTN = SEC_RtnHead(SEC); RTN_Valid(RTN); RTN = RTN_Next(RTN)){
      if (RTN_Valid(RTN)){
        RTN_Open(RTN);
        RTN_InsertCall(RTN, IPOINT_BEFORE, (AFUNPTR)OnFunctionEntry,
          IARG_THREAD_ID,
          IARG_RETURN_IP,
          IARG_PTR, RTN_Name(RTN).c_str(),
          IARG_END);
        RTN_Close(RTN);
      }
    }
  }
}

void Thread_OnInit(THREADID Tid, CONTEXT* ctxt, INT32 flags, void* v){
  VM_REG[Tid] = (u8*)calloc(17 + 64 + 1, 1);
  if (!VM_REG[Tid]) __debugbreak();
}

void OnContextChange(THREADID tid, CONTEXT_CHANGE_REASON reason,
  const CONTEXT* ctxtFrom, CONTEXT* ctxtTo,
  INT32 info, void* v){

  if (reason == CONTEXT_CHANGE_REASON_EXCEPTION){
    ADDRINT exceptionAddress = PIN_GetContextReg(ctxtFrom, REG_INST_PTR);
    __LOG("Exception Address: %llx\nDetails: %x\n", exceptionAddress, info);
  }
}

void OnSyscallEntry(THREADID Tid, CONTEXT* ctxt, SYSCALL_STANDARD std, void* v){
  ADDRINT sys_num = PIN_GetSyscallNumber(ctxt, std);
  ADDRINT IP = PIN_GetContextReg(ctxt, REG_INST_PTR);
  if (IsAddressExcluded(IP))
    return;
  taint_write(VM_REG[Tid], 8, 8, Msk(8));
  __LOG("%llx Syscall %llx\n", IP, sys_num);
}

int main(int argc, char** argv){
  PIN_Init(argc, argv);
  PIN_InitSymbols();
  PIN_AddApplicationStartFunction(Engine_OnInit, 0);
  IMG_AddInstrumentFunction(IMG_OnLoad, 0);
  PIN_AddThreadStartFunction(Thread_OnInit, 0);
  PIN_AddInternalExceptionHandler(MyExceptionHandler, 0);
  PIN_AddSyscallEntryFunction(OnSyscallEntry, 0);
  PIN_AddContextChangeFunction(OnContextChange, 0);
  INS_AddInstrumentFunction(Instru_x86, 0);
  PIN_StartProgram();
  return 0;
}