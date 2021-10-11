{$S-,R-,B-}
unit Unit1;
interface
uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls,
  Forms, Dialogs, tlHelp32,  ExtCtrls, FileCtrl, ComCtrls,
  StdCtrls, Grids, Menus, shellApi, psApi,
  {Для автозагрузки:} activeX,shlObj,comobj;

const
info=
'Программа антивирус'#13#10+
'Ловит вирусы в процессах, а как поймает запоминает и удаляет.'#13#10+
'Можно нажать правую кнопку мыши и указать тип процесса:'#13#10+
'вредно - сразу удалить'#13#10+
'полезно - никогда не удалять'#13#10+
'Ctrl - не удалять только если нажата Ctrl при запуске'#13#10+
'Можно использовать для запрета запуска посторонним'#13#10+
'или для запрета запуска 2-ой копии'#13#10#13#10+
'последняя версия в programania.com/pc.zip'#13#10;

MyTrayIcon = WM_USER + 1;

type
  TForm1 = class(TForm)
    Timer1: TTimer;
    StringGrid1: TStringGrid;
    Label1: TLabel;
    Label2: TLabel;
    PopupMenu1: TPopupMenu;
    N1: TMenuItem;
    N2: TMenuItem;
    N3: TMenuItem;
    N4: TMenuItem;
    N5: TMenuItem;
    N6: TMenuItem;
    N7: TMenuItem;
    N8: TMenuItem;
    N9: TMenuItem;
    N10: TMenuItem;
    N11: TMenuItem;
    N14: TMenuItem;
    N15: TMenuItem;
    N16: TMenuItem;
    Ctrl: TMenuItem;
    N17: TMenuItem;
    N12: TMenuItem;
    HIGHPRIORITYCLASS1: TMenuItem;
    IDLEPRIORITYCLASS1: TMenuItem;
    NORMALPRIORITYCLASS1: TMenuItem;
    REALTIMEPRIORITYCLASS1: TMenuItem;
    procedure Timer1Timer(Sender: TObject);
    procedure StringGrid1DrawCell(Sender: TObject; ACol, ARow: Integer;
      R: TRect; State: TGridDrawState);
    procedure FormCreate(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
    procedure StringGrid1MouseDown(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
    procedure StringGrid1KeyDown(Sender: TObject; var Key: Word;
      Shift: TShiftState);
    procedure FormResize(Sender: TObject);
    procedure N1Click(Sender: TObject);
    procedure N2Click(Sender: TObject);
    procedure N3Click(Sender: TObject);
    procedure N4Click(Sender: TObject);
    procedure N6Click(Sender: TObject);
    procedure N8Click(Sender: TObject);
    procedure N9Click(Sender: TObject);
    procedure N10Click(Sender: TObject);
    procedure N11Click(Sender: TObject);
    procedure N14Click(Sender: TObject);
    procedure N15Click(Sender: TObject);
    procedure PopupMenu1Popup(Sender: TObject);
    procedure N16Click(Sender: TObject);
    procedure CtrlClick(Sender: TObject);
    procedure N17Click(Sender: TObject);
    procedure HIGHPRIORITYCLASS1Click(Sender: TObject);
    procedure NORMALPRIORITYCLASS1Click(Sender: TObject);
    procedure IDLEPRIORITYCLASS1Click(Sender: TObject);
    procedure REALTIMEPRIORITYCLASS1Click(Sender: TObject);
  protected
  procedure WMGetSysCommand(var Message :TMessage); message WM_SYSCOMMAND;

  private
    { Private declarations }
    procedure MTIcon(var a: TMessage); message MyTrayIcon;
  public
    { Public declarations }
  end;

type
tm= record
 n   :string; //название процесса
 path:string; //путь к exe процесса
 a:boolean;   //активно
 k:boolean;   //убить
 t:char;      //w-вредно p-полезно n-не знаю с-ctrl
 q:byte;      //номер по порядку у одинаковых
 d:integer;   //дата появления
 pr:dWord;     //<>0 - установить приоритет
end;

var
Form1: TForm1;
m:array of tm;
p:array of tm;
p1:tm;
mf: array of char;
f:file;
t:textFile;
hn,wn,tn,ln,rrr:integer;
qm:integer=0;
qp:integer=0;
qmp:integer=0; //прошлая qm
sr:integer=0;  //выделенная строка
xm,ym:integer; //координаты меню
aCol:integer;  //колонка сортировки
wTimer:boolean=false;
nr:byte=0;
td:string;
s:string;
en:string; //exeName;
ini:string;
sCol:byte;//колонка сортировки
su:boolean;//сортировка по убыванию
zKill:byte=0; //>0было запущено удаление чтоб не добавлять
zKillM:boolean=false; //было запущено удаление через меню
NID: TNotifyIconData;
uwn:boolean=false;//убивать все новые
nw :boolean=false;//новые считать вредными
nCtrl:boolean=true;//Ctrl не нажато

implementation

{$R *.DFM}
PROCEDURE wHide;
begin
Application.ShowMainForm := false;
with NID do begin
  cbSize := SizeOf(TNotifyIconData);
  Wnd := form1.handle;
  uId := 1;
  uFlags := NIF_ICON or NIF_MESSAGE or NIF_TIP;
  uCallbackMessage := MyTrayIcon;
  hIcon := Application.Icon.Handle;
  szTip := 'Слежу за процессами';
end;
Shell_NotifyIcon(NIM_ADD, @NID);
end;

procedure TForm1.WMGetSysCommand(var Message : TMessage) ;
begin
if (Message.wParam = SC_MINIMIZE) then begin
// Application.Minimize;
 Shell_NotifyIcon(NIM_ADD, @NID);
 visible:=false;
end
else inherited;
end;

PROCEDURE uqp;
begin
inc(qp);
if qp>=length(p) then setLength(p,length(p)+100);
end;

FUNCTION ok(qs:integer):string;
var m10:byte;
begin
m10:=qs mod 10;
if (qs in [11..19]) or (m10 in [0,5..9])then ok:='ов' else
if m10=1 then ok:='' else ok:='а';
end;

PROCEDURE wl1;
begin
form1.label1.caption:='Помню '+intToStr(qp)+' процесс'+ok(qp);
end;

PROCEDURE pAlign;
begin
with form1 do begin
  stringGrid1.height:=clientHeight-stringGrid1.top;
  stringGrid1.width :=clientWidth;
end;
end;

function KillProcess(ProcessID: DWORD): boolean;
var
hProcess: THandle;
hToken: THandle;
Priv,PrivOld: TOKEN_PRIVILEGES;
cbPriv: DWORD;
dwError: DWORD;
begin
hProcess:=OpenProcess(PROCESS_TERMINATE,false,ProcessID);
if hProcess = 0 then
 begin
  cbPriv:=SizeOf(PrivOld);
  // Для Win2k
  OpenThreadToken(GetCurrentThread,TOKEN_QUERY or TOKEN_ADJUST_PRIVILEGES,false,hToken);
  OpenProcessToken(GetCurrentProcess,TOKEN_QUERY or  TOKEN_ADJUST_PRIVILEGES,hToken);
  //
  Priv.PrivilegeCount:=1;
  Priv.Privileges[0].Attributes:=SE_PRIVILEGE_ENABLED;
  LookupPrivilegeValue(nil,'SeDebugPrivilege',Priv.Privileges[0].Luid);
  AdjustTokenPrivileges(hToken,false,Priv,SizeOf(Priv),PrivOld,cbPriv);
  hProcess:=OpenProcess(PROCESS_TERMINATE,false,ProcessID);
  dwError:=GetLastError;
  cbPriv:=0;
  AdjustTokenPrivileges(hToken,false,PrivOld,SizeOf(PrivOld),nil,cbPriv);
  CloseHandle(hToken);
 end;
 TerminateProcess(hProcess,$FFFFFFFF);
 CloseHandle(hProcess);
 Result:=true;
end;

FUNCTION CtrlDown: Boolean;
begin
result:=GetKeyState(VK_CONTROL) < 0;
end;

procedure TForm1.Timer1Timer(Sender: TObject);

var
handler:thandle;
data:tagPROCESSENTRY32;
 pID,dwError:DWORD;
 hProc:THandle;
 Buf:Array [0..255] Of Char;
 i:integer;

Function obr:string;
var
s,path:string;
q,j:integer;
proc:thandle;
zs:boolean; //запущено сейчас

begin
s:=trim(ansiLowerCase(data.szExeFile));
hProc:=OpenProcess(PROCESS_ALL_ACCESS,True,data.th32ProcessID);
GetModuleFileNameEx(hProc,0,Buf,256);
path:=ansiLowerCase(Buf);
if (path<>'')and(path[1]<>'?')
   then path:=extractFileDir(path)
   else path:=extractFileDir(s);
s:=extractFileName(s); //для 98
q:=0;
for j:=1 to qm do if s=m[j].n then inc(q);
inc(qm);
if qm>=length(m) then setLength(m,length(m)+100);
m[qm].q:=q;
m[qm].n:=s;
m[qm].t:=' ';
//добавка новых в p
j:=1;
while (j<=qp)and((s<>p[j].n)or(q<>p[j].q)) do inc(j);

zs:=(qm>qmp)and(j<=qp);
if zs and(p[j].t='w') and CtrlDown then p[j].t:=' ';

if j>qp then begin
  uqp;
  p[qp].q:=q;
  p[qp].n:=s;
  p[qp].t:=' ';
  if nw and nCtrl then p[qp].t:='w';
  p[qp].d:=DateTimeToFileDate(now);
  p[j].path:='';
  p[j].k:=uwn and nCtrl;
  p[j].pr:=0;
end;

p[j].a:=true;

if p[j].pr<>0 then begin
  SetPriorityClass(hProc,p[j].pr);
  p[j].pr:=0;
end;

if path<>'' then p[j].path:=path;

if zs and (p[j].t='c') and nCtrl then p[j].k:=true;

if (p[j].t='w') or p[j].k then KillProcess(data.th32ProcessID);

p[j].k:=false;
end;


BEGIN
if wTimer then exit;
wTimer:=true;

if nr=1 then begin
  StringGrid1.RowCount:=qp+1;
  StringGrid1.rePaint;
  if hn>0 then begin height:=hn; hn:=0; width:=wn end;
end;

handler:=createtoolhelp32snapshot(TH32CS_SNAPALL,0);
data.dwSize:=sizeOf(data);
if handler>0 then begin
if process32first(handler,data) then begin
  qm:=0;
  nCtrl:=not CtrlDown;
  for i:=1 to qp do p[i].a:=false;
  repeat
    obr;
  until not process32next(handler,data);
  qmp:=qm;
end;
CloseHandle(handler);
end;

if qp>0 then begin wl1; nr:=1; end;

wTimer:=false;
end;


PROCEDURE usr(aRow:integer);
begin
with form1.label2 do
if (aRow>0)and(aRow<=qp) then begin
  sr:=aRow;
  visible:=true;
  caption:=p[sr].n;
end
else caption:='';
end;

PROCEDURE kc(r,g,b:integer);
var c,z:integer; m:array[1..4] of byte absolute c;

Function o(z:integer):integer;
begin
if z>255 then o:=255 else if z<0 then o:=0 else o:=z;
end;

begin
//корекция цвета
c:=form1.stringGrid1.canvas.brush.color;
m[1]:=o(m[1]+r);
m[2]:=o(m[2]+g);
m[3]:=o(m[3]+b);
form1.stringGrid1.canvas.brush.color:=c;
end;

procedure TForm1.StringGrid1DrawCell(Sender: TObject; ACol, ARow: Integer;
  R: TRect; State: TGridDrawState);
var
s:string;
cw:integer;
begin
if qp=0 then exit;
with StringGrid1.Canvas do begin
pen.color:=$C0C0CC;
if (aRow<qp) then r:=rect(r.left,r.top,r.right,r.bottom+1);
if (aCol<stringGrid1.colCount-1) then r:=rect(r.left,r.top,r.right+1,r.bottom);
s:='';
if aRow=0 then begin
  brush.color:=$B0C2E0;//$B0C0D0;
  pen.color:=$A0A0AA;
  font.color:=$F0FFFF;
  rectangle(r);
  case aCol of
    0:s:='Процесс';
    1:s:='Тип';
    2:s:='Состояние';
    3:s:='Появилось';
    4:s:='Nпп';
    5:s:='Путь';
  end;
end
else begin
  font.color:=$8088A8;
  if gdSelected in State then begin
    brush.color:=$D8E8FF; usr(aRow);
  end
  else brush.color:=$F0F8FF;

  if aRow<=qp then with p[aRow] do begin
// текст
  case aCol of
   0: s:=n;
   1: case t of
       'p':s:='полезно'; 'w':s:='вредно';'c':s:='Ctrl'; else s:='не знаю';
      end;
   2: if a then s:='активно' else s:='спит';
   3: s:=FormatDateTime('dd.mm.yy hh:nn',FileDateToDateTime(d));
   4: if q>0 then s:=intToStr(q);
   5: begin s:=path;
       cw:=stringGrid1.ColWidths[5]-14;
       while (s<>'')and(textWidth(s)>cw) do setLength(s,length(s)-1);
       if length(s)<length(path) then s:=s+'...';
      end;
  end;

// цвет
  case t of
    'p':begin kc(-10,5,10);  font.color:=$BB8888 end;
    'w':begin kc(10,-20,-20);font.color:=$FF end;
  end;
  if a then
  if aCol=2 then begin kc(80,-10,-20);font.color:=$8888DD end
  else kc(5,-5,-5);

  end;
  rectangle(r);
  if gdSelected in State then begin
     pen.Color:=$A0C0FF;
     moveTo(r.left,r.top+1); lineTo(r.right,r.top+1);
     moveTo(r.left,r.bottom-2); lineTo(r.right,r.bottom-2);
  end;
end;
textOut(r.left+3,r.top+3,s);
end;

nr:=0;
end;

Function wel(c:char):string;
var se:string; i:integer;
begin
//выделение элемента до символа c из s
se:='';
i:=1;
while (i<=length(s))and(s[i]<>c) do begin
  se:=se+s[i];
  inc(i);
end;
wel:=trim(se);
delete(s,1,i);
end;

procedure TForm1.FormCreate(Sender: TObject);
var
 sr,z:string;
 g:byte;
 dt:tdatetime;
 i:integer;
 //tc:cardinal;
begin
//if ctrlDown then qp:=0;
hn:=500; wn:=325; ln:=360; tn:=120;
height:=56;
ShortDateFormat:='dd.MM.yyyy';
stringGrid1.GridLineWidth:=0;
stringGrid1.color:=$F0F8FF;
color:=$DFEFFF;
label1.font.color:=$97A8DB;
label2.font.color:=$7788BB;
en:=application.exeName;

ini:=extractFilePath(en)+'PC.ini';
assignFile(t,ini);
{$i-}reset(t);{$i+}
if ioresult<>0 then rewrite(t) else
while not eof(t) do begin
  readln(t,s);
  i:=pos('=',s);
  if pos(#9,s)>0 then begin
    uqp;
    with p[qp] do begin
      wel(#9);
      n:=wel(#9);
      sr:=wel(#9); if sr='' then t:=' ' else t:=sr[1];
      sr:=wel(#9);
      d:=DateTimeToFileDate(StrToDateTime(sr));
      dt:=FileDateToDateTime(d);
      q:=strToIntDef(wel(#9),0);
      path:=wel(#9);
    end;
  end
  else
  if i>0 then begin
    sr:=copy(s,1,i-1);
    z:=copy(s,i+1,$FFFF);
    if sr='Высота' then hn:=strToIntDef(z,500);
    if sr='Ширина' then wn:=strToIntDef(z,325);
    if sr='Лево'   then ln:=strToIntDef(z,360);
    if sr='Верх'   then tn:=strToIntDef(z,120);
    if sr='Убивай новые' then uwn:=bool(strToIntDef(z,0));
    if sr='Новые-вредные' then nw:=bool(strToIntDef(z,0));
  end;
end;

left:=ln;
top:=tn;
closeFile(t);

wHide;
if (paramCount=0) or (paramStr(1)<>'/h') then begin
  Shell_NotifyIcon(NIM_DELETE, @NID);
  show
end;
end;

PROCEDURE save;
var i:integer; si:string;
begin
with form1 do begin
assignFile(f,ini);
reset(f,1);
s:=info+
'Высота='+intToStr(height)+#13#10+
'Ширина='+intToStr(width)+#13#10+
'Верх='+intToStr(top)+#13#10+
'Лево='+intToStr(left)+#13#10+
'Убивай новые='+intToStr(ord(uwn))+#13#10+
'Новые-вредные='+intToStr(ord(nw))+#13#10;

for i:=1 to qp do with p[i] do begin
  si:=n; while length(si)<20 do si:=si+' ';
  s:=s+'Процесс='#9+si+#9+t+#9+
    FormatDateTime('dd.mm.yy hh:nn',FileDateToDateTime(d))+#9+
    intToStr(q)+#9+path+#13#10;
  blockWrite(f,s[1],length(s));
  s:='';
end;
truncate(f);
closeFile(f);
end;
end;

procedure TForm1.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
save;
end;

PROCEDURE sort;
var
i,j1,g1,r:integer;  ns:boolean;
Function srw:boolean;
begin
r:=j1+g1;
with p[j1] do
  case aCol of
    0: if n<p[r].n then srw:=su else
       if n>p[r].n then srw:=ns else srw:=false;
    1: if t<p[r].t then srw:=su else
       if t>p[r].t then srw:=ns else srw:=false;
    2: if a<p[r].a then srw:=su else
       if a>p[r].a then srw:=ns else srw:=false;
    3: if d<p[r].d then srw:=su else
       if d>p[r].d then srw:=ns else srw:=false;
    4: if q<p[r].q then srw:=su else
       if q>p[r].q then srw:=ns else srw:=false;
    5: if path<p[r].path then srw:=su else
       if path>p[r].path then srw:=ns else srw:=false;
  end;
end;

begin
//сортировка
g1:=qp;
ns:=not su;
while g1>0 do begin
  g1:=g1 div 2;
  i:=g1;
  while i<qp do begin
    j1:=i-g1+1;
    while (j1>=1) and srw do begin
      r:=j1+g1;
      p1:=p[j1]; p[j1]:=p[r]; p[r]:=p1;
      dec(j1,g1)
    end;
    inc(i);
  end;
end;
end;

procedure TForm1.StringGrid1MouseDown(Sender: TObject;
  Button: TMouseButton; Shift: TShiftState; X, Y: Integer);
var aRow,xm,ym:integer;   r: TGridRect;

begin
StringGrid1.MouseToCell(X, Y, aCol, aRow);
if arow=0 then begin
  if aCol=sCol then su:=not su else su:=false;
  sCol:=aCol;
  sort; StringGrid1.rePaint; exit;
end;

usr(aRow);
r.top:=aRow; r.bottom:=aRow; r.left:=0; r.right:=StringGrid1.ColCount-1;
StringGrid1.selection:=r;
nr:=2;
StringGrid1.rePaint;
if button=mbRight then begin
  N6.visible:=not p[sr].a;
  popupMenu1.popup(X+left,Y+top+StringGrid1.top+30);
end;
end;

procedure TForm1.StringGrid1KeyDown(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
if key=112{F1} then showMessage(info);
nr:=2; StringGrid1.rePaint;
end;

procedure TForm1.FormResize(Sender: TObject); begin
pAlign;
end;

PROCEDURE uTip(t:char);
begin
p[sr].t:=t;
nr:=2;
form1.StringGrid1.rePaint;
end;

procedure TForm1.N1Click(Sender: TObject);begin uTip('p') end;
procedure TForm1.N2Click(Sender: TObject);begin uTip('w') end;
procedure TForm1.N3Click(Sender: TObject);begin uTip(' ') end;
procedure TForm1.CtrlClick(Sender: TObject);begin uTip('c') end;

procedure TForm1.N4Click(Sender: TObject);
var i:integer;
begin
dec(qp);
for i:=sr to qp do p[i]:=p[i+1];
nr:=2;
form1.StringGrid1.rePaint;
wl1;
end;

procedure TForm1.N6Click(Sender: TObject);
begin
s:=p[sr].path+'\'+p[sr].n;
ShellExecute(0,'open', pChar(s),nil,pChar(p[sr].path),SW_NORMAL);
end;

PROCEDURE obrF(imf:string);
begin
inc(rrr);
end;

var
DirBytes : int64;
ns:string;
function scan(Dir:string):integer;
var
sr: TSearchRec;
e,r : string;
begin
if Copy(Dir,Length(Dir),1)='\' then r:= '' else r:='\';
if FindFirst(Dir+r+'*.*',faAnyFile,sr) = 0 then begin
  repeat
    if FileExists(Dir+r+sr.Name) then begin
      DirBytes:=DirBytes+sr.Size;
      if ansiLowerCase(sr.name)=ns then
      s:=dir;
      e:=lowerCase(extractFileExt(sr.name));
      if (e='.dll')or(e='.exe') then
      inc(rrr);
//    Dir+r+sr.Name - файл
    end
    else
    if DirectoryExists(Dir+r+sr.Name) then begin
      if (sr.Name<>'.') and (sr.Name<>'..') then
        scan(Dir+r+sr.Name);
    end;
  until FindNext(sr)<>0;
end;
FindClose(sr);
end;

procedure TForm1.N11Click(Sender: TObject);
var path:array[0..MAX_PATH] of char;
begin
GetWinDowsDirectory(path,MAX_PATH);
DirBytes:=0;
ns:=p[sr].n;
s:='';
scan(strPas(path));
if s<>'' then begin p[sr].path:=s; stringGrid1.repaint; end;
end;

FUNCTION pp(id:word):string;
var
PIDList:PItemIDList;
path:array[0..MAX_PATH] of char;
begin
//получение типового пути
pp:='';
if SHGetSpecialFolderLocation(form1.handle,id,PIDList)=NOERROR
then begin
  SHGetPathFromIDList(PIDList,Path);
  pp:=strPas(path)+'\';
end;
end;

PROCEDURE CreateLink(const pathObj,PathLink,Descript,Params,pathI: string);
var
shellLink:IshellLink;
iObject:IUnknown;
LinkFile:iPersistFile;
begin
  iObject:=createComObject(CLSID_ShellLink);
  LinkFile:=IObject as IPersistFile;
  ShellLink:=IObject as IShellLink;
  with ShellLink do begin
    SetPath(PChar(pathObj));
    SetArguments(PChar(params));
    SetDescription(PChar(Descript));
    SetIconLocation(PChar(pathI),0);
  end;
  LinkFile.Save(PWChar(WideString(PathLink)),false);
end;

PROCEDURE startUP(z:boolean; pa:string);
var
lnk:string;
begin
//запись в автозагрузку с параметром pa
s:=pp(CSIDL_STARTUP);
if s<>'' then begin
  lnk:=s+'\'+'PC_Auto.lnk';
  if z then CreateLink(en,lnk,'',pa,en)
       else deleteFile(lnk);
end;
end;

procedure TForm1.N8Click(Sender: TObject);begin startUP(true,'') end;
procedure TForm1.N9Click(Sender: TObject);begin startUP(false,'') end;
procedure TForm1.N10Click(Sender: TObject);begin startUP(true,'/h')end;

procedure TForm1.MTIcon(var a: TMessage);
var P: TPoint;
begin
if (a.lParam=WM_LBUTTONDOWN)or(a.lParam=WM_RBUTTONUP) then begin
  show;
  SetForegroundWindow(Handle);
  application.processMessages;
//удаление значка
  Shell_NotifyIcon(NIM_DELETE, @NID);
end;
end;

procedure TForm1.N14Click(Sender: TObject);
begin
p[sr].k:=true
end;

procedure TForm1.N15Click(Sender: TObject);
begin
uwn:=not uwn;
end;

procedure TForm1.PopupMenu1Popup(Sender: TObject);
begin
N15.checked:=uwn;
N16.checked:=nw;
end;

procedure TForm1.N16Click(Sender: TObject);
begin
nw:=not nw;
end;

procedure TForm1.N17Click(Sender: TObject);
begin
showMessage(info);
end;

procedure TForm1.HIGHPRIORITYCLASS1Click(Sender: TObject);
begin
p[sr].pr:=HIGH_PRIORITY_CLASS;
end;

procedure TForm1.NORMALPRIORITYCLASS1Click(Sender: TObject);
begin
p[sr].pr:=NORMAL_PRIORITY_CLASS
end;

procedure TForm1.IDLEPRIORITYCLASS1Click(Sender: TObject);
begin
p[sr].pr:=IDLE_PRIORITY_CLASS;
end;

procedure TForm1.REALTIMEPRIORITYCLASS1Click(Sender: TObject);
begin
p[sr].pr:=REALTIME_PRIORITY_CLASS;
end;

end.

{
Можно сравнить процессы на разных компьютерах:
перенести PC.ini на другой и посмотреть время появления
равное текущему это будут новые процессы которые есть на
этом и нет на другом
winlgon-цветовые схемы
wmiprvse.exe tcpsvcs.exe MsPMSPSv.exe CTSVCCDA.EXE полезные
GetProcessTimes
}


