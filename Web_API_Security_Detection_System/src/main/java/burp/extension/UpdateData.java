package burp.extension;

public class UpdateData {
    //标识
    public static int PAYLOAD_ADD = 0;
    public static int PAYLOAD_COVER = 1;
    public static int PAYLOAD_CLEAN = 2;
    public static int PAYLOAD_HEADER = 3;
    public static int PAYLOAD_BODY = 4;
    public static int PAYLOAD_PATH = 5;
    public static int PAYLOAD_PARAM = 6;
    public static int PAYLOAD_INNER = 7;
    public static int PAYLOAD_OUTER = 8;

    private int method;
    private int position;
    private int inOrOut;
    private String keys;
    private String value;
    private boolean isNULL; //判断内部存储是否为空

//    UpdateData(int  method,int position,int inOrOut,String keys,String value){
//        this.method = method;
//        this.position = position;
//        this.inOrOut = inOrOut;
//        this.keys = keys;
//        this.value = value;
//    }
public UpdateData(){
        isNULL = true;method = position = inOrOut = -1;keys = value = null;
    }
    //getter方法
    public int getMthod(){
        return this.method;
    }

    public int getPosition() {
        return position;
    }

    public int getInOrOut() {
        return inOrOut;
    }

    public String getKeys() {
        return keys;
    }

    public String getValue() {
        return value;
    }

    public boolean getIsNULL() {
        return isNULL;
    }

    //setter方法
    public void setMethod(int method) {
        this.method = method;
    }

    public void setPosition(int position) {
        this.position = position;
    }

    public void setInOrOut(int inOrOut) {
        this.inOrOut = inOrOut;
    }

    public void setKeys(String keys) {
        this.keys = keys;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public void setIsNULL(boolean NULL) {
        isNULL = NULL;
    }

}
