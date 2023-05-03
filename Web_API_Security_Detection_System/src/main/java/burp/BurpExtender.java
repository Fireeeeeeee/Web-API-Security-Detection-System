package burp;


import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


import burp.extension.*;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;


import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;



public class BurpExtender implements IBurpExtender ,ITab{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    //部分组件
    private JRadioButton  addButton;
    private JRadioButton  coverButton;
    private JRadioButton  cleanButton;
    private ButtonGroup methodButtonGroup;
    private JRadioButton  headerButton;
    private JRadioButton  bodyButton;
    private JRadioButton  pathButton;
    private JRadioButton  paramButton;
    private ButtonGroup positionButtonGroup;
    private JRadioButton  innerButton;
    private JRadioButton  outerButton;
    private ButtonGroup inOrOutButtonGroup;
    private JTextField keyText;
    private JTextField valueText;
    private JRadioButton stringJRadioButton;
    private JRadioButton dnslogJRadioButton;
    private JRadioButton serverJRadioButton;
    private JRadioButton timeJRadioButton;
    private ButtonGroup judgeSelect;
    private JComboBox dnslogMehtodSelect;//dnslog平台选择

    private JTabbedPane root;
    private JTextField filePath; //导入http包的路径
    private int proxyUse;//决定是否使用proxy模块监听到的包
    private RequestResponseClass[] proxyMessage; //保存proxy的HTTP包
    private RequestResponseClass[] importMessage; //保存导入的HTTP包
    private int proxyMessageNum = 0;//proxy的HTTP包的数量
    private int importMessageNum = 0; //导入的HTTP包的数量
    private HashMap<Integer, RequestResponseClass> hashMap = new HashMap<Integer, RequestResponseClass>();//保存所有数据

    //Judge板块
    private String judgeText; //字符串判断的目标字符串
    private JTextField ceyeDnsDomain; //dnslog ceye平台的标识符，也就是域名
    private JTextField ceyeToken;      //dnslog ceye平台的接口API token
    private JTextField serverIp;     //服务器判断方法 接收外带数据的服务器ip
    private JTextField serverPort;     //服务器判断方法 接收外带数据的服务器端口
    private JTextField fileName;       //服务器判断方法 接收外带数据的服务器保存的文件
    private JTextField filePort;       //服务器判断方法 接收外带数据的服务器保存的文件的访问端口  http服务方式访问，使用python的http.server
    private JTextField timeNum;      //Time Delay判断方法 延迟时间长度

    private DefaultListModel payloaddata = new DefaultListModel();

    //Excute板块
    private JTable displayTable;//excute板块的包信息表格
    private DefaultTableModel tableData;//excute板块的包信息表格数据
    private int tableItemNum = 0;//excute板块的表格item条数
    private JTabbedPane beforeRequestResponsePanel;//修改前的包信息面板
    private JTabbedPane afterRequestResponsePanel;//修改后的包信息面板
    private JTextArea beforeRequestText;//显示修改前的请求包的JTextArea组件
    private JTextArea beforeResponseText;
    private JTextArea afterRequestText;//显示修改后的请求包的JTextArea组件
    private JTextArea afterResponseText;
    private JTextArea tipsArea;
    private AtomicBoolean isStopped = new AtomicBoolean(false);
    private AtomicBoolean isStart = new AtomicBoolean(false);
    private ExecutorService executor;

    private int updateNum = 10;
    private UpdateData[] updateData; //excute面板的Insert Payload数据
    private int lastIndex = 0;


    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.callbacks = iBurpExtenderCallbacks;
        this.helpers = iBurpExtenderCallbacks.getHelpers();
        callbacks.setExtensionName("Web API Security Detection System");
        updateData  = new UpdateData[updateNum];
        for(int i=0;i<updateNum;i++){
            updateData[i] = new UpdateData();
        }

        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                BurpExtender.this.root = new JTabbedPane(); //创建基点

                //创建select功能的UI panel
                JPanel selectPane = BurpExtender.this.createSelectPanel();
                JScrollPane selectScrollPane = new JScrollPane(selectPane);
                BurpExtender.this.root.addTab("select",(Icon)null,selectScrollPane,"收集器");

                //创建input功能的UI panel
                JTabbedPane inputPane = BurpExtender.this.createInputPanel();
                BurpExtender.this.root.addTab("input",(Icon)null,inputPane,"用例器");

                //创建judge功能的UI panel
                JPanel judgePane = BurpExtender.this.createJudgePanel();
                JScrollPane judgeScrollPane = new JScrollPane(judgePane);
                BurpExtender.this.root.addTab("judge",(Icon)null,judgeScrollPane,"判断器");

                //创建excute功能的UI panel
                JPanel excutePane = BurpExtender.this.createExcutePanel();
                JScrollPane excuteScrollPane = new JScrollPane(excutePane);
                BurpExtender.this.root.addTab("excute",(Icon)null,excuteScrollPane,"执行器");


                //总体渲染
                callbacks.customizeUiComponent(BurpExtender.this.root);
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }
    public JPanel createSelectPanel(){
        JPanel selectPane = new JPanel();
        selectPane.setLayout(new GridBagLayout());
        //selectPane.setBorder(BorderFactory.createTitledBorder("测试范围"));
        int yPosition = 0;
        int tmpy = yPosition + 1;
        Insets SelectPanelInsets = new Insets(10, 10, 10, 10);

        //是否使用代理模式的数据包pannel
        GridBagConstraints proxyOrNotConstraints = new GridBagConstraints();
        proxyOrNotConstraints.gridx = 0;
        proxyOrNotConstraints.gridy = yPosition;
        proxyOrNotConstraints.ipadx = 5;
        proxyOrNotConstraints.ipady = 5;
        proxyOrNotConstraints.insets = SelectPanelInsets;
        proxyOrNotConstraints.anchor = GridBagConstraints.NORTHWEST;
        selectPane.add(buildProxyOrNotPanel(),proxyOrNotConstraints);
        //第一条分割线
        JSeparator LocalFilePanelSeparator = new JSeparator(0);
        this.callbacks.customizeUiComponent(LocalFilePanelSeparator);
        GridBagConstraints localFilePanelSeparatorConstraints = new GridBagConstraints();
        localFilePanelSeparatorConstraints.gridx = 0;
        localFilePanelSeparatorConstraints.gridy = tmpy++;
        localFilePanelSeparatorConstraints.insets = SelectPanelInsets;
        localFilePanelSeparatorConstraints.fill = GridBagConstraints.HORIZONTAL;
        localFilePanelSeparatorConstraints.anchor = GridBagConstraints.NORTH;
        selectPane.add(LocalFilePanelSeparator, localFilePanelSeparatorConstraints);

        //本地文件选择功能panel
        GridBagConstraints LocalFilePanelConstraints = new GridBagConstraints();
        LocalFilePanelConstraints.gridx = 0;
        LocalFilePanelConstraints.gridy = tmpy++;
        LocalFilePanelConstraints.ipadx = 5;
        LocalFilePanelConstraints.ipady = 5;
        LocalFilePanelConstraints.insets = SelectPanelInsets;
        LocalFilePanelConstraints.anchor = GridBagConstraints.NORTHWEST;
        selectPane.add(buildLocalFilePanel(tmpy),LocalFilePanelConstraints);
        //第二条分割线
        JSeparator LocalFilePanelSeparator1 = new JSeparator(0);
        this.callbacks.customizeUiComponent(LocalFilePanelSeparator1);
        GridBagConstraints localFilePanelSeparatorConstraints1 = new GridBagConstraints();
        localFilePanelSeparatorConstraints1.gridx = 0;
        localFilePanelSeparatorConstraints1.gridy = tmpy++;
        localFilePanelSeparatorConstraints1.insets = SelectPanelInsets;
        localFilePanelSeparatorConstraints1.fill = GridBagConstraints.HORIZONTAL;
        localFilePanelSeparatorConstraints1.anchor = GridBagConstraints.NORTH;
        selectPane.add(LocalFilePanelSeparator1, localFilePanelSeparatorConstraints1);
        //扩展
        GridBagConstraints LocalFilePanelConstraints1 = new GridBagConstraints();
        LocalFilePanelConstraints1.gridx = 0;
        LocalFilePanelConstraints1.gridy = tmpy++;
        LocalFilePanelConstraints1.ipadx = 5;
        LocalFilePanelConstraints1.ipady = 5;
        LocalFilePanelConstraints1.weightx  = 1.0D;
        LocalFilePanelConstraints1.weighty = 1.0D;
        //LocalFilePanelConstraints1.fill=GridBagConstraints.BOTH;
        LocalFilePanelConstraints1.insets = SelectPanelInsets;
        LocalFilePanelConstraints1.anchor = GridBagConstraints.NORTHWEST;
        selectPane.add(new JPanel(),LocalFilePanelConstraints1);

        return  selectPane;
    }

    public JTabbedPane createInputPanel(){
        JTabbedPane inputPane = new JTabbedPane();
        //本地导入用例功能panel
        JPanel localInputPane = BurpExtender.this.createlocalInputPanel();
        JScrollPane localInputScrollPane = new JScrollPane(localInputPane);
        inputPane.addTab("local",(Icon)null,localInputScrollPane,"本地");

        //扩展导入用例功能panel
        JPanel extendInputPane = BurpExtender.this.createextendInputPane();
        JScrollPane extendInputScrollPane = new JScrollPane(extendInputPane);
        inputPane.addTab("extend",(Icon)null,extendInputScrollPane,"扩展");

        return  inputPane;
    }

    public JPanel createlocalInputPanel(){
        JPanel localInputPane = new JPanel();
        localInputPane.setLayout(new GridBagLayout());
        //localInputPane.setBorder(BorderFactory.createTitledBorder("测试范围"));
        int yPosition = 0;
        int tmpy = yPosition + 1;
        Insets localInputPanelInsets = new Insets(10, 10, 10, 10);
        //
        GridBagConstraints localInputConstraint = new GridBagConstraints();
        localInputConstraint.gridx = 0;
        localInputConstraint.gridy = yPosition;
        localInputConstraint.ipadx = 5;
        localInputConstraint.ipady = 5;
        //localInputConstraint.fill = GridBagConstraints.NORTHWEST;
        localInputConstraint.anchor = GridBagConstraints.NORTHWEST;
        localInputConstraint.insets = localInputPanelInsets;
//        localInputConstraint.weightx  = 1.0D;
//        localInputConstraint.weighty = 1.0D;
        localInputPane.add(buildLocalPayloadInputPanel(tmpy),localInputConstraint);
        //第一条分割线
        JSeparator localInputPanelSeparator = new JSeparator(0);
        this.callbacks.customizeUiComponent(localInputPanelSeparator);
        GridBagConstraints localInputPanelSeparatorConstraints = new GridBagConstraints();
        localInputPanelSeparatorConstraints.gridx = 0;
        localInputPanelSeparatorConstraints.gridy = tmpy++;
        localInputPanelSeparatorConstraints.insets = localInputPanelInsets;
        localInputPanelSeparatorConstraints.fill = GridBagConstraints.HORIZONTAL;
        localInputPanelSeparatorConstraints.anchor = GridBagConstraints.NORTH;
        localInputPane.add(localInputPanelSeparator, localInputPanelSeparatorConstraints);
        //添置物
        GridBagConstraints localInputConstraint1 = new GridBagConstraints();
        localInputConstraint1.gridx = 0;
        localInputConstraint1.ipadx = 5;
        localInputConstraint1.ipady = 5;
        //localInputConstraint1.fill = GridBagConstraints.NORTHWEST;
        localInputConstraint1.anchor = GridBagConstraints.NORTH;
        localInputConstraint1.insets = localInputPanelInsets;
        localInputConstraint1.weightx  = 1.0D;
        localInputConstraint1.weighty = 1.0D;
        localInputConstraint1.gridy = tmpy++;
        JPanel jPanel = new JPanel();
        localInputPane.add(jPanel,localInputConstraint1);


        return localInputPane;
    }


    public JPanel createJudgePanel(){
        JPanel judgePane = new JPanel();
        judgePane.setLayout(new GridBagLayout());
        int yPosition = 0;
        Insets JudgePanelInsets = new Insets(10, 10, 10, 10);

        //字符串判断功能panel
        GridBagConstraints stringConstraints = new GridBagConstraints();
        stringConstraints.gridx = 0;
        stringConstraints.gridy = yPosition;
        stringConstraints.ipadx = 5;
        stringConstraints.ipady = 5;
        stringConstraints.insets = JudgePanelInsets;
        stringConstraints.anchor = GridBagConstraints.NORTHWEST;
        judgePane.add(buildStringPanel(),stringConstraints);

        //第一条分割线
        JSeparator judgePanelSeparator = new JSeparator(0);
        this.callbacks.customizeUiComponent(judgePanelSeparator);
        GridBagConstraints judgePanelSeparatorConstraints = new GridBagConstraints();
        judgePanelSeparatorConstraints.gridx = 0;
        judgePanelSeparatorConstraints.gridy = ++yPosition;
        judgePanelSeparatorConstraints.insets = JudgePanelInsets;
        judgePanelSeparatorConstraints.fill = GridBagConstraints.HORIZONTAL;
        judgePanelSeparatorConstraints.anchor = GridBagConstraints.NORTH;
        judgePane.add(judgePanelSeparator, judgePanelSeparatorConstraints);

        //dnslog功能Panel
        GridBagConstraints dnslogConstraints = new GridBagConstraints();
        dnslogConstraints.gridx = 0;
        dnslogConstraints.gridy = ++yPosition;
        dnslogConstraints.ipadx = 5;
        dnslogConstraints.ipady = 5;
        dnslogConstraints.insets = JudgePanelInsets;
        dnslogConstraints.anchor = GridBagConstraints.NORTHWEST;
        judgePane.add(buildDnslogPanel(),dnslogConstraints);

        //第二条分割线
        JSeparator judgePanelSeparator1 = new JSeparator(0);
        this.callbacks.customizeUiComponent(judgePanelSeparator);
        judgePanelSeparatorConstraints.gridy = ++yPosition;
        judgePane.add(judgePanelSeparator1, judgePanelSeparatorConstraints);

        //服务器判断功能Panel
        GridBagConstraints serverConstraints = new GridBagConstraints();
        serverConstraints.gridx = 0;
        serverConstraints.gridy = ++yPosition;
        serverConstraints.ipadx = 5;
        serverConstraints.ipady = 5;
        serverConstraints.insets = JudgePanelInsets;
        serverConstraints.anchor = GridBagConstraints.NORTHWEST;
        judgePane.add(buildServerPanel(),serverConstraints);



        //第三条分割线
        JSeparator judgePanelSeparator2 = new JSeparator(0);
        this.callbacks.customizeUiComponent(judgePanelSeparator);
        judgePanelSeparatorConstraints.gridy = ++yPosition;
        judgePane.add(judgePanelSeparator2, judgePanelSeparatorConstraints);

        //Time判断功能Panel 延迟判断
        GridBagConstraints timeConstraints = new GridBagConstraints();
        timeConstraints.gridx = 0;
        timeConstraints.gridy = ++yPosition;
        timeConstraints.ipadx = 5;
        timeConstraints.ipady = 5;
        timeConstraints.insets = JudgePanelInsets;
        timeConstraints.anchor = GridBagConstraints.NORTHWEST;
        judgePane.add(buildTimePanel(),timeConstraints);

        //第四条分割线
        JSeparator judgePanelSeparator3 = new JSeparator(0);
        this.callbacks.customizeUiComponent(judgePanelSeparator);
        judgePanelSeparatorConstraints.gridy = ++yPosition;
        judgePane.add(judgePanelSeparator3, judgePanelSeparatorConstraints);

        //填充
        GridBagConstraints paddingConstraints = new GridBagConstraints();
        paddingConstraints.gridx = 0;
        paddingConstraints.gridy = ++yPosition;
        paddingConstraints.ipadx = 5;
        paddingConstraints.ipady = 5;
        paddingConstraints.insets = JudgePanelInsets;
        paddingConstraints.anchor = GridBagConstraints.NORTHWEST;
        paddingConstraints.weightx  = 1.0D;
        paddingConstraints.weighty = 1.0D;
        JPanel padding = new JPanel();
        judgePane.add(padding,paddingConstraints);

        return  judgePane;
    }


    public JPanel createExcutePanel(){
        JPanel excutePanel = new JPanel();
        excutePanel.setLayout(new BorderLayout());

        //通过两个JSplitPane分割三部分：包列表展示、包详细信息展示、payload插入方式
        JSplitPane secondSplitPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT,buildDisplayDetailPanel(),buildInsertPositionPanel());
        JSplitPane firstSplitPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT,buildDisplayListPanel(),secondSplitPanel);
        //firstSplitPanel.setBorder(BorderFactory.createTitledBorder("测试范围"));
        excutePanel.add(firstSplitPanel,BorderLayout.CENTER);
        return  excutePanel;
    }

    public JPanel buildProxyOrNotPanel(){
        JPanel proxyOrNotPanel = new JPanel();
        proxyOrNotPanel.setLayout(new GridBagLayout());

        int xPosition = 0;
        this.addPanelTitleToGridBagLayout("Use Proxy Module",proxyOrNotPanel,0,0);

        final JRadioButton proxyButton = new JRadioButton("Proxy");
        proxyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(proxyButton.isSelected()){
                    BurpExtender.this.proxyUse = 1;
                    IHttpRequestResponse[] iHttpRequestResponses = callbacks.getProxyHistory();
                    BurpExtender.this.proxyMessage = new RequestResponseClass[iHttpRequestResponses.length];
                    for( IHttpRequestResponse httpRequestResponse:iHttpRequestResponses){
                        BurpExtender.this.proxyMessage[proxyMessageNum] = new RequestResponseClass(helpers.analyzeRequest(httpRequestResponse.getRequest()),httpRequestResponse.getRequest());
                        hashMap.put(BurpExtender.this.proxyMessage[proxyMessageNum].getHashcode(),BurpExtender.this.proxyMessage[proxyMessageNum]);
                        proxyMessageNum++;
                    }
                }else{
                    for(RequestResponseClass requestresponseclass:BurpExtender.this.proxyMessage){
                        hashMap.remove(requestresponseclass.getHashcode());
                    }
                    BurpExtender.this.proxyUse = 0;
                    BurpExtender.this.proxyMessage = null;
                    proxyMessageNum = 0;
                }
            }
        });
        GridBagConstraints proxyButtonConstraints = new GridBagConstraints();
        proxyButtonConstraints.gridx = 0;
        proxyButtonConstraints.gridy = 1;
        proxyButtonConstraints.gridwidth = 1;
        proxyButtonConstraints.ipadx = 5;
        proxyButtonConstraints.ipady = 5;
        proxyOrNotPanel.add(proxyButton,proxyButtonConstraints);

        return proxyOrNotPanel;
    }
    public JPanel buildLocalFilePanel(int yPosition){
        final JPanel localFilePanel = new JPanel();
        localFilePanel.setLayout(new GridBagLayout());
        //localFilePanel.setBorder(BorderFactory.createTitledBorder("测试范围1"));

        int xPosition = 0;
        this.addPanelTitleToGridBagLayout("Local File",localFilePanel,0,0);

        //
        JLabel textFieldLabel = new JLabel("Directory：");
        this.callbacks.customizeUiComponent(textFieldLabel);
        textFieldLabel.setHorizontalAlignment(2);
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridwidth = 1;
        gridBagConstraints.gridx = xPosition;
        gridBagConstraints.gridy = ++yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        gridBagConstraints.fill = 1;
        localFilePanel.add(textFieldLabel, gridBagConstraints);
        //文件路径地址 输入框
        BurpExtender.this.filePath = new JTextField(50);
        gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = xPosition + 1;
        gridBagConstraints.gridy = yPosition;
        localFilePanel.add(filePath,gridBagConstraints);

        //三个按钮设置
        JButton selectButton = new JButton("Select");
        gridBagConstraints.gridx = xPosition + 2;
        gridBagConstraints.gridy = yPosition;
        localFilePanel.add(selectButton,gridBagConstraints);
        selectButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser chooser = new JFileChooser();
                String currentDirectory = BurpExtender.this.filePath.getText();
                if (currentDirectory == null || currentDirectory.trim().equals("")) {
                    currentDirectory = System.getProperty("user.home");
                }
                chooser.setCurrentDirectory(new File(currentDirectory));
                chooser.setDialogTitle("Please select the directory of the target file");
                chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                chooser.setAcceptAllFileFilterUsed(false);
                if(chooser.showOpenDialog(localFilePanel) == 0){
                    BurpExtender.this.filePath.setText(chooser.getSelectedFile().getAbsolutePath());
                    //等下写入全局配置文件
                }
            }
        });

        JButton inputButton = new JButton("Import");
        gridBagConstraints.gridx = xPosition + 3;
        gridBagConstraints.gridy = yPosition;
        localFilePanel.add(inputButton,gridBagConstraints);
        inputButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String currentDirectory = BurpExtender.this.filePath.getText().trim();
                if (currentDirectory != null && !currentDirectory.trim().equals("")) {
                    if(BurpExtender.this.importMessage != null) {
                        for (RequestResponseClass requestresponseclass : BurpExtender.this.importMessage) {
                            if(requestresponseclass!=null) {
                                if (hashMap.get(requestresponseclass.getHashcode()) != null)
                                    hashMap.remove(requestresponseclass.getHashcode());
                            }else{
                                System.out.println("导入按钮：requestresponseclass is Null!");
                            }
                        }
                    }
                    File filelist = new File(currentDirectory);
                    if(filelist.isDirectory()) {
                        BurpExtender.this.importMessage = new RequestResponseClass[filelist.listFiles().length];
                        BurpExtender.this.importMessageNum = 0;
                        for (File file : filelist.listFiles()) {
                            if (file.isFile()) {
                                try {
                                    byte[] request = myselfFile.toByteArray(file.getAbsolutePath());
                                    BurpExtender.this.importMessage[BurpExtender.this.importMessageNum] = new RequestResponseClass(BurpExtender.this.helpers.analyzeRequest(request), request);
                                    hashMap.put(BurpExtender.this.importMessage[BurpExtender.this.importMessageNum].getHashcode(), BurpExtender.this.importMessage[BurpExtender.this.importMessageNum]);
                                    BurpExtender.this.importMessageNum++;
                                } catch (FileNotFoundException fileNotFoundException) {
                                    fileNotFoundException.printStackTrace();
                                } catch (IOException ioException) {
                                    ioException.printStackTrace();
                                }
                            }
                        }
                    }else{
                        System.out.println("This is not a directory!");
                    }
                }
            }
        });

        JButton deleteButton = new JButton("Clear");
        gridBagConstraints.gridx = xPosition + 4;
        gridBagConstraints.gridy = yPosition;
        localFilePanel.add(deleteButton,gridBagConstraints);
        deleteButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(BurpExtender.this.importMessage != null) {
                    for (RequestResponseClass requestresponseclass : BurpExtender.this.importMessage) {
                        if(requestresponseclass!=null) {
                            if (hashMap.get(requestresponseclass.getHashcode()) != null)
                                hashMap.remove(requestresponseclass.getHashcode());
                        }else{
                            System.out.println("清空按钮：requestresponseclass is Null!");
                        }
                    }
                }
                BurpExtender.this.importMessage = null;
                BurpExtender.this.importMessageNum = 0;
            }
        });

        return localFilePanel;
    }

    public JPanel buildLocalPayloadInputPanel(int yPosition){
        final JPanel localInputPane = new JPanel();
        localInputPane.setLayout(new GridBagLayout());
        //localInputPane.setBorder(BorderFactory.createTitledBorder("测试范围1"));
        Insets localPayloadInputPanelInsets = new Insets(1, 1, 1, 1);
        //添加title
        this.addPanelTitleToGridBagLayout("Payload options",localInputPane,0,0);

        //添加所有按钮
        int tmpy = yPosition + 1;
        int xPostion = 0;
        GridBagConstraints buttonPanelConstraints = new GridBagConstraints();
        buttonPanelConstraints.ipadx = 5;
        buttonPanelConstraints.ipady = 5;
        buttonPanelConstraints.gridheight = 1;
        buttonPanelConstraints.gridwidth = 1;
        buttonPanelConstraints.fill = GridBagConstraints.BOTH;
        buttonPanelConstraints.insets = localPayloadInputPanelInsets;

        final JButton pasteButton = new JButton("Paste");
        buttonPanelConstraints.gridx = xPostion;
        buttonPanelConstraints.gridy = tmpy++;
        localInputPane.add(pasteButton,buttonPanelConstraints);

        JButton loadButton = new JButton("Load");
        buttonPanelConstraints.gridx = xPostion;
        buttonPanelConstraints.gridy = tmpy++;
        localInputPane.add(loadButton,buttonPanelConstraints);

        JButton removeButton = new JButton("Remove");
        buttonPanelConstraints.gridy = tmpy++;
        localInputPane.add(removeButton,buttonPanelConstraints);

        final JButton clearButton = new JButton("Clear");
        buttonPanelConstraints.gridy = tmpy++;
        localInputPane.add(clearButton,buttonPanelConstraints);

        JButton addButton = new JButton("Add");
        buttonPanelConstraints.gridy = ++tmpy;
        buttonPanelConstraints.insets = new Insets(20,1,1,1);
        localInputPane.add(addButton,buttonPanelConstraints);


        //添加内容框
        GridBagConstraints showPanelConstraints = new GridBagConstraints();
        showPanelConstraints.ipadx = 5;
        showPanelConstraints.ipady = 5;
        showPanelConstraints.gridwidth = 1;
        showPanelConstraints.fill = GridBagConstraints.BOTH;
        showPanelConstraints.insets = localPayloadInputPanelInsets;

        final JList inputList = new JList(BurpExtender.this.payloaddata);
        inputList.setVisibleRowCount(5);
        JScrollPane inputListScrollPane = new JScrollPane(inputList);
        showPanelConstraints.gridx = xPostion+1;
        showPanelConstraints.gridy = 2;
        showPanelConstraints.gridheight = 5;
        localInputPane.add(inputListScrollPane,showPanelConstraints);

        //添加输入框
        final JTextField inputExample = new JTextField(30);
        showPanelConstraints.gridx = xPostion+1;
        showPanelConstraints.gridy = tmpy;
        //showPanelConstraints.weighty = 1;
        showPanelConstraints.gridheight = 1;
        showPanelConstraints.insets = new Insets(20,1,1,1);
        localInputPane.add(inputExample,showPanelConstraints);



        //所有监听器
        //--paste按钮
        pasteButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String ret = "";
                Clipboard sysClip = Toolkit.getDefaultToolkit().getSystemClipboard();
                // 获取剪切板中的内容
                Transferable clipTf = sysClip.getContents(null);
                if (clipTf != null) {
                    // 检查内容是否是文本类型
                    if (clipTf.isDataFlavorSupported(DataFlavor.stringFlavor)) {
                        try {
                            ret = (String) clipTf
                                    .getTransferData(DataFlavor.stringFlavor);
                        } catch (Exception ee) {
                            ee.printStackTrace();
                        }
                    }
                }
                BurpExtender.this.payloaddata.addElement(ret);
            }
        });
        //--Load按钮
        loadButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser chooser = new JFileChooser();
                chooser.setCurrentDirectory(new File(System.getProperty("user.home")));
                chooser.setDialogTitle("Please select the file of payload");
                chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                chooser.setAcceptAllFileFilterUsed(false);
                if(chooser.showOpenDialog(localInputPane) == 0){
                    String path = chooser.getSelectedFile().getAbsolutePath();
                    if (path != null && !path.trim().equals("")) {
                        File paylaodfile = new File(path);
                        if(paylaodfile.isFile()){
                            try {
                                FileReader fis = new FileReader(paylaodfile);
                                BufferedReader br = new BufferedReader(fis);
                                String payload = br.readLine();
                                while(payload != null){
                                    BurpExtender.this.payloaddata.addElement(payload);
                                    payload = br.readLine();
                                }
                                br.close();
                            } catch (FileNotFoundException ee) {
                                ee.printStackTrace();
                            } catch (IOException ioException) {
                                ioException.printStackTrace();
                            }
                        }
                    }
                }
            }
        });
        //--Remove按钮
        removeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                 int[] indexs =inputList.getSelectedIndices();
                 if(!inputList.isSelectionEmpty()){
                     for(int i :indexs){
                         BurpExtender.this.payloaddata.remove(i);
                     }
                 }
            }
        });
        //--Clear按钮
        clearButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                BurpExtender.this.payloaddata.clear();
            }
        });

        //--Add按钮
        addButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String payload = inputExample.getText();
                if(!payload.equals("")){
                    BurpExtender.this.payloaddata.addElement(payload);
                    inputExample.setText("");
                }
            }
        });
        return  localInputPane;
    }

    public JPanel createextendInputPane(){
        JPanel extendInputPane = new JPanel();


        return  extendInputPane;
    }

    public JPanel buildStringPanel(){
        JPanel stringPanel = new JPanel();
        stringPanel.setLayout(new GridBagLayout());
        //stringPanel.setBorder(BorderFactory.createTitledBorder("测试范围1"));
        int xPosition = 0;
        //添加标题
        this.addPanelTitleToGridBagLayout("String Judge",stringPanel,0,0);

        //添加可编辑框
        final JTextArea stringArea = new JTextArea(12,100);
        Font font = new Font("Arial", Font.PLAIN, 28);
        stringArea.setFont(font);
        stringArea.setEditable(false);
        JScrollPane stringAreaScrollPanel = new JScrollPane(stringArea);
        GridBagConstraints stringAreaConstraints = new GridBagConstraints();
        stringAreaConstraints.gridx = 0;
        stringAreaConstraints.gridy = 1;
        stringAreaConstraints.gridwidth = 1;
        stringAreaConstraints.gridheight = 10;
        stringAreaConstraints.weightx = 5 ;
        stringAreaConstraints.fill = GridBagConstraints.HORIZONTAL;
        stringAreaConstraints.anchor = GridBagConstraints.NORTH;
        stringPanel.add(stringAreaScrollPanel,stringAreaConstraints);

        //添加按钮
        JButton editButton = new JButton("Edit");
        editButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                stringArea.setEditable(true);
            }
        });
        GridBagConstraints buttonConstraints = new GridBagConstraints();
        buttonConstraints.ipadx = 5;
        buttonConstraints.ipady = 5;
        buttonConstraints.gridx = 1;
        buttonConstraints.gridy = 1;
        buttonConstraints.gridwidth = 1;
        buttonConstraints.gridheight = 1;
        stringAreaConstraints.weightx = 1.0D;
        stringPanel.add(editButton,buttonConstraints);

        JButton agreeButton = new JButton("Conf");
        agreeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                stringArea.setEditable(false);
                BurpExtender.this.judgeText = stringArea.getText();
            }
        });
        buttonConstraints.gridx = 1;
        buttonConstraints.gridy = 2;
        stringPanel.add(agreeButton,buttonConstraints);

        return stringPanel;
    }
    public JPanel buildDnslogPanel(){
        final JPanel dnslogPanel = new JPanel();
        dnslogPanel.setLayout(new GridBagLayout());
        this.addPanelTitleToGridBagLayout("Dnslog Judge",dnslogPanel,0,0);

        dnslogMehtodSelect = new JComboBox(new String[]{"Ceye平台", "其余"});

        final JPanel optionPanel = new JPanel(); // 新建一个 JPanel，用来放置 JComboBox 和 ceyePanel
        optionPanel.setLayout(new GridBagLayout());
        optionPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        final JPanel ceyePanel = buildCeyePanel();
        final JPanel leftPanel = buildLeftPanel();

        // Add the JComboBox to optionPanel
        GridBagConstraints dnslogPanelConstraints = new GridBagConstraints();
        dnslogPanelConstraints.gridx = 0;
        dnslogPanelConstraints.gridy = 1;
        dnslogPanelConstraints.anchor = GridBagConstraints.WEST;
        optionPanel.add(dnslogMehtodSelect, dnslogPanelConstraints);

        // Add the ceyePanel to optionPanel
        dnslogPanelConstraints = new GridBagConstraints();
        dnslogPanelConstraints.gridx = 0;
        dnslogPanelConstraints.gridy = 2;
        dnslogPanelConstraints.anchor = GridBagConstraints.WEST;
        optionPanel.add(ceyePanel, dnslogPanelConstraints);

        // Add the optionPanel to dnslogPanel
        dnslogPanelConstraints = new GridBagConstraints();
        dnslogPanelConstraints.gridx = 0;
        dnslogPanelConstraints.gridy = 1;
        dnslogPanelConstraints.anchor = GridBagConstraints.WEST;
        dnslogPanel.add(optionPanel, dnslogPanelConstraints);

        // Add the leftPanel to dnslogPanel
        dnslogPanelConstraints = new GridBagConstraints();
        dnslogPanelConstraints.gridx = 0;
        dnslogPanelConstraints.gridy = 2;
        dnslogPanelConstraints.anchor = GridBagConstraints.WEST;
        dnslogPanel.add(leftPanel, dnslogPanelConstraints);

        ceyePanel.setVisible(true); // 初始时将 ceyePanel 显示出来
        leftPanel.setVisible(false); // 初始时将 leftPanel 隐藏起来

        dnslogMehtodSelect.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String selectedOption = (String) dnslogMehtodSelect.getSelectedItem();
                if(selectedOption.equals("Ceye平台")){
                    ceyePanel.setVisible(true); // 将 ceyePanel 显示出来
                    leftPanel.setVisible(false);
                }else if(selectedOption.equals("其余")){
                    ceyePanel.setVisible(false);
                    leftPanel.setVisible(true); // 将 leftPanel 显示出来
                }//.......
            }
        });

        return dnslogPanel;
    }

    public JPanel buildCeyePanel(){
        JPanel ceyePanel = new JPanel(new GridBagLayout());
        GridBagConstraints ceyePanelConstraints = new GridBagConstraints();
        ceyePanelConstraints.insets = new Insets(0, 0, 0, 5); // add some padding between components

        // Ceye标识符 label and text field
        ceyePanelConstraints.gridx = 0;
        ceyePanelConstraints.gridy = 0;
        ceyePanelConstraints.anchor = GridBagConstraints.LINE_START;
        ceyePanelConstraints.insets = new Insets(10, 0, 0, 5);
        JLabel ceyeSignLabel = new JLabel("Ceye标识符：");
        ceyePanel.add(ceyeSignLabel, ceyePanelConstraints);

        ceyePanelConstraints.gridx = 1;
        ceyePanelConstraints.gridy = 0;
        ceyePanelConstraints.anchor = GridBagConstraints.LINE_START;
        ceyeDnsDomain = new JTextField(25);
        ceyePanel.add(ceyeDnsDomain, ceyePanelConstraints);

        // Ceye API Token label and text field
        ceyePanelConstraints.gridx = 0;
        ceyePanelConstraints.gridy = 1;
        ceyePanelConstraints.anchor = GridBagConstraints.LINE_START;
        ceyePanelConstraints.insets = new Insets(0, 0, 0, 5);
        JLabel ceyeAPITokenLabel = new JLabel("Ceye API Token：");
        ceyePanel.add(ceyeAPITokenLabel, ceyePanelConstraints);

        ceyePanelConstraints.gridx = 1;
        ceyePanelConstraints.gridy = 1;
        ceyePanelConstraints.anchor = GridBagConstraints.LINE_START;
        ceyeToken = new JTextField(25);
        ceyePanel.add(ceyeToken, ceyePanelConstraints);

        return ceyePanel;
    }
    public JPanel buildLeftPanel(){
        JPanel leftPanel = new JPanel();
        leftPanel.add(new TextArea());
        return leftPanel;
    }

    public JPanel buildServerPanel(){
        JPanel serverPanel = new JPanel();
        serverPanel.setLayout(new GridBagLayout());
        GridBagConstraints serverPanelConstraints = new GridBagConstraints();

        this.addPanelTitleToGridBagLayout("Server Judge",serverPanel,0,0);

        serverPanelConstraints.gridx = 0;
        serverPanelConstraints.gridy = 1;
        serverPanelConstraints.anchor = GridBagConstraints.NORTH;
        serverPanel.add(buildDetailServerPanel(), serverPanelConstraints);

        return serverPanel;
    }

    public JPanel buildDetailServerPanel(){
        JPanel detailServerPanel = new JPanel();
        detailServerPanel.setLayout(new GridBagLayout());
        GridBagConstraints serverPanelConstraints = new GridBagConstraints();
        serverPanelConstraints.insets = new Insets(0, 0, 0, 5); // add some padding between components

        // serverIP label and text field
        serverPanelConstraints.gridx = 0;
        serverPanelConstraints.gridy = 0;
        serverPanelConstraints.anchor = GridBagConstraints.LINE_START;
        serverPanelConstraints.insets = new Insets(10, 0, 0, 5);
        JLabel serverIPLabel = new JLabel("serverIP：");
        detailServerPanel.add(serverIPLabel, serverPanelConstraints);

        serverPanelConstraints.gridx = 1;
        serverPanelConstraints.gridy = 0;
        serverPanelConstraints.anchor = GridBagConstraints.LINE_START;
        serverIp = new JTextField(25);
        detailServerPanel.add(serverIp, serverPanelConstraints);

        // serverPORT label and text field
        serverPanelConstraints.gridx = 0;
        serverPanelConstraints.gridy = 1;
        serverPanelConstraints.anchor = GridBagConstraints.LINE_START;
        serverPanelConstraints.insets = new Insets(0, 0, 0, 5);
        JLabel serverPORTLabel = new JLabel("serverPORT：");
        detailServerPanel.add(serverPORTLabel, serverPanelConstraints);


        serverPanelConstraints.gridx = 1;
        serverPanelConstraints.gridy = 1;
        serverPanelConstraints.anchor = GridBagConstraints.LINE_START;
        serverPort = new JTextField(25);
        detailServerPanel.add(serverPort, serverPanelConstraints);


        JButton serverTipsButton = new JButton("Code");
        serverPanelConstraints.gridx = 2;
        serverPanelConstraints.gridy = 1;
        detailServerPanel.add(serverTipsButton, serverPanelConstraints);
        serverTipsButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JTextArea textArea = new JTextArea();
                textArea.setEditable(false);
                textArea.setText("import asyncio\n" +
                        "\n" +
                        "# 定义一个IP地址和端口号\n" +
                        "host = \"0.0.0.0\" # 监听所有网卡\n" +
                        "port = 9000\n" +
                        "\n" +
                        "# 定义一个处理函数，用于接收数据并将其存储到文件中\n" +
                        "async def handle_client(reader, writer):\n" +
                        "    # 读取数据\n" +
                        "    data = await reader.read(1024)\n" +
                        "    if not data:\n" +
                        "        return\n" +
                        "    \n" +
                        "    # 将接收到的数据写入文件\n" +
                        "    with open('received_data.txt', 'a') as f:\n" +
                        "        f.write(str(writer.get_extra_info('peername')) + ': ' + data.decode() + '\\n')\n" +
                        "    \n" +
                        "    # 关闭连接\n" +
                        "    writer.close()\n" +
                        "\n" +
                        "# 启动服务器并接收连接\n" +
                        "async def main():\n" +
                        "    server = await asyncio.start_server(handle_client, host, port)\n" +
                        "    async with server:\n" +
                        "        await server.serve_forever()\n" +
                        "\n" +
                        "# 开始运行程序\n" +
                        "asyncio.run(main())");
                JScrollPane scrollPane = new JScrollPane(textArea);
                JOptionPane.showMessageDialog(null, scrollPane,"服务器接收外带数据代码的示例代码", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        // fileNAME label and text field
        serverPanelConstraints.gridx = 0;
        serverPanelConstraints.gridy = 2;
        serverPanelConstraints.anchor = GridBagConstraints.LINE_START;
        serverPanelConstraints.insets = new Insets(0, 0, 0, 5);
        JLabel fileNAMELabel = new JLabel("fileNAME：");
        detailServerPanel.add(fileNAMELabel, serverPanelConstraints);

        serverPanelConstraints.gridx = 1;
        serverPanelConstraints.gridy = 2;
        serverPanelConstraints.anchor = GridBagConstraints.LINE_START;
        fileName = new JTextField(25);
        detailServerPanel.add(fileName, serverPanelConstraints);


        // filePORT label and text field
        serverPanelConstraints.gridx = 0;
        serverPanelConstraints.gridy = 3;
        serverPanelConstraints.anchor = GridBagConstraints.LINE_START;
        serverPanelConstraints.insets = new Insets(0, 0, 0, 5);
        JLabel filePORTLabel = new JLabel("filePORT：");
        detailServerPanel.add(filePORTLabel, serverPanelConstraints);


        serverPanelConstraints.gridx = 1;
        serverPanelConstraints.gridy = 3;
        serverPanelConstraints.anchor = GridBagConstraints.LINE_START;
        filePort = new JTextField(25);
        detailServerPanel.add(filePort, serverPanelConstraints);

        JButton fileTipsButton = new JButton("Code");
        serverPanelConstraints.gridx = 2;
        serverPanelConstraints.gridy = 3;
        detailServerPanel.add(fileTipsButton, serverPanelConstraints);
        fileTipsButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JTextArea textArea = new JTextArea();
                textArea.setEditable(false);
                textArea.setText("from http.server import HTTPServer, SimpleHTTPRequestHandler\n" +
                        "\n" +
                        "class MyRequestHandler(SimpleHTTPRequestHandler):\n" +
                        "    \n" +
                        "    # 重写do_GET方法，在请求某个资源时进行权限控制\n" +
                        "    def do_GET(self):\n" +
                        "        if self.path != '/received_data.txt':\n" +
                        "            self.send_error(404, \"File not found\")\n" +
                        "        else:\n" +
                        "            return super().do_GET()\n" +
                        "\n" +
                        "# 指定监听地址和端口号\n" +
                        "host = ''\n" +
                        "port = 8000\n" +
                        "\n" +
                        "# 创建HTTP服务器，并指定请求处理函数\n" +
                        "httpd = HTTPServer((host, port), MyRequestHandler)\n" +
                        "\n" +
                        "# 启动HTTP服务器\n" +
                        "print(f\"Server started on http://{host}:{port}\")\n" +
                        "httpd.serve_forever()");
                JScrollPane scrollPane = new JScrollPane(textArea);
                JOptionPane.showMessageDialog(null, scrollPane,"服务器访问外带数据文件的示例代码", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        return  detailServerPanel;
    }

    public JPanel buildTimePanel(){
        JPanel timePanel = new JPanel();
        timePanel.setLayout(new GridBagLayout());
        GridBagConstraints timePanelConstraints = new GridBagConstraints();

        this.addPanelTitleToGridBagLayout("Time Delay Judge",timePanel,0,0);

        // Ceye标识符 label and text field
        timePanelConstraints.gridx = 0;
        timePanelConstraints.gridy = 1;
        timePanelConstraints.anchor = GridBagConstraints.LINE_START;
        timePanelConstraints.insets = new Insets(10, 0, 0, 5);
        JLabel timeLabel = new JLabel("Time(s)：");
        timePanel.add(timeLabel, timePanelConstraints);

        timePanelConstraints.gridx = 1;
        timePanelConstraints.gridy = 1;
        timePanelConstraints.anchor = GridBagConstraints.LINE_START;
        timeNum = new JTextField(25);
        timeNum.setText("3");
        timePanel.add(timeNum, timePanelConstraints);


        return timePanel;
    }

    public JPanel buildDisplayListPanel(){
        JPanel displayListPanel = new JPanel();
        //displayListPanel.setBorder(BorderFactory.createTitledBorder("测试范围1"));
        displayListPanel.setLayout(new BorderLayout());

        //表格设计
        //Object[] tableColumnTitle = {"#","HOST","Method","URL","Status","Length","MIME type","Port","Cookies","Result"};//10个
        BurpExtender.this.tableData = new DefaultTableModel (new Object[][]{}, new String[]{"#","HOST","Method","URL","Status","Length","MIME type","Port","Cookies","Result"});
        BurpExtender.this.displayTable = new JTable(BurpExtender.this.tableData){
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        BurpExtender.this.displayTable.setFillsViewportHeight(true);
        BurpExtender.this.displayTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        BurpExtender.this.displayTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() { //设置新的渲染器
            public Component getTableCellRendererComponent(JTable table, Object value,
                                                           boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

                // check the value of the "Result" column for the current row
                Object statusValue = table.getValueAt(row, 9);
                if (statusValue != null && statusValue.equals("Success")) {
                    c.setBackground(Color.RED);
                } else if(statusValue != null && statusValue.equals("Failure")){
                    c.setBackground(Color.YELLOW);
                }else{
                    c.setBackground(Color.WHITE);
                }
                return c;
            }
        });
        JScrollPane displayTableScrollPanel = new JScrollPane(BurpExtender.this.displayTable);
        displayListPanel.add(displayTableScrollPanel,"Center");

        /*---监听器---*/
        /*呈现被选中的包的完整信息*/
        BurpExtender.this.displayTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int row = BurpExtender.this.displayTable.getSelectedRow();
                if(row != -1){//getBeforeRequestText
                    beforeRequestText.setText("");
                    afterRequestText.setText("");
                    afterResponseText.setText("");
                    Object hashid = BurpExtender.this.displayTable.getValueAt(row,0);
                    beforeRequestText.setText(hashMap.get(Integer.parseInt(String.valueOf(hashid))).getBeforeRequestText());
                    afterRequestText.setText(hashMap.get(Integer.parseInt(String.valueOf(hashid))).getAfterRequestText());
                    IHttpRequestResponse iHttpRequestResponse = hashMap.get(Integer.parseInt(String.valueOf(hashid))).getAfterRequest().getResponse();
                    if(iHttpRequestResponse!=null&&iHttpRequestResponse.getResponse()!=null){
                        afterResponseText.setText(helpers.bytesToString(iHttpRequestResponse.getResponse()));
                    }
                }
            }
        });
        return displayListPanel;
    }

    public JTabbedPane buildDisplayDetailPanel(){
        JTabbedPane displayDetailTabPanel = new JTabbedPane();
        beforeRequestResponsePanel = buildBeforeRequestResponsePanel();
        afterRequestResponsePanel = buildAfterRequestResponsePanel();
        displayDetailTabPanel.addTab("Before",(Icon)null,beforeRequestResponsePanel,"修改前的包");
        displayDetailTabPanel.addTab("After",(Icon)null,afterRequestResponsePanel,"修改后的包");

        return displayDetailTabPanel;
    }

    public JTabbedPane buildBeforeRequestResponsePanel(){
        JTabbedPane beforeRequestResponseTabPanel = new JTabbedPane();
        beforeRequestText = new JTextArea();
        beforeRequestText.setEditable(false);
        JScrollPane beforeRequestTextScrollPanel = new JScrollPane(beforeRequestText);
        beforeResponseText = new JTextArea();
        beforeResponseText.setEditable(false);
        JScrollPane beforeResponseTextScrollPanel = new JScrollPane(beforeResponseText);
        beforeRequestResponseTabPanel.addTab("Request",(Icon)null,beforeRequestTextScrollPanel,"请求包");
        beforeRequestResponseTabPanel.addTab("Response",(Icon)null,beforeResponseTextScrollPanel,"响应包");
        return beforeRequestResponseTabPanel;
    }

    public JTabbedPane buildAfterRequestResponsePanel(){
        JTabbedPane afterRequestResponseTabPanel = new JTabbedPane();

        afterRequestText = new JTextArea();
        afterRequestText.setEditable(false);
        JScrollPane afterRequestTextScrollPanel = new JScrollPane(afterRequestText);
        afterResponseText = new JTextArea();
        afterResponseText.setEditable(false);
        JScrollPane afterResponseTextScrollPanel = new JScrollPane(afterResponseText);

        afterRequestResponseTabPanel.addTab("Request",(Icon)null,afterRequestTextScrollPanel,"请求包");
        afterRequestResponseTabPanel.addTab("Response",(Icon)null,afterResponseTextScrollPanel,"响应包");

        return afterRequestResponseTabPanel;
    }

    public JPanel buildInsertPositionPanel(){
        JPanel insertPositionPanel = new JPanel();
        insertPositionPanel.setLayout(new GridBagLayout());
        //insertPositionPanel.setBorder(BorderFactory.createTitledBorder("测试范围"));


        //选择judge模式的按钮
        int yPosition = 0;
        GridBagConstraints judgeSelectPanelConstraints = new GridBagConstraints();
        judgeSelectPanelConstraints.gridx = 0;
        judgeSelectPanelConstraints.gridy = yPosition++;
        judgeSelectPanelConstraints.gridwidth = 1;
        judgeSelectPanelConstraints.fill = GridBagConstraints.HORIZONTAL;
        judgeSelectPanelConstraints.anchor = GridBagConstraints.NORTHWEST;
        insertPositionPanel.add(buildJudgeSelectPanel(),judgeSelectPanelConstraints);

        //第一条分割线
        JSeparator insertPositionPanelJSeparator = new JSeparator(0);
        this.callbacks.customizeUiComponent(insertPositionPanelJSeparator);
        GridBagConstraints insertPositionPanelJSeparatorConstraints = new GridBagConstraints();
        insertPositionPanelJSeparatorConstraints.gridy = 0;
        insertPositionPanelJSeparatorConstraints.gridy = yPosition++;
        insertPositionPanelJSeparatorConstraints.fill = GridBagConstraints.HORIZONTAL;
        insertPositionPanelJSeparatorConstraints.anchor = GridBagConstraints.NORTH;
        insertPositionPanelJSeparatorConstraints.insets = new Insets(10, 10, 10, 10);
        insertPositionPanel.add(insertPositionPanelJSeparator,insertPositionPanelJSeparatorConstraints);

        //第二个组件
        GridBagConstraints judgeSelectPanelConstraints1 = new GridBagConstraints();
        judgeSelectPanelConstraints1.weightx =1.0D;
        judgeSelectPanelConstraints1.weighty =1.0D;
        judgeSelectPanelConstraints1.gridy = yPosition++;
        judgeSelectPanelConstraints1.gridx = 0;
        judgeSelectPanelConstraints1.ipadx = 5;
        judgeSelectPanelConstraints1.ipady = 5;
        judgeSelectPanelConstraints1.anchor = GridBagConstraints.NORTHWEST;
        insertPositionPanel.add(buildPayloadInsertPannel(),judgeSelectPanelConstraints1);



        return insertPositionPanel;
    }

    public JPanel buildPayloadInsertPannel(){
        JPanel payloadInsertPannel = new JPanel();
        payloadInsertPannel.setLayout(new GridBagLayout());

        //添加标题
        this.addPanelTitleToGridBagLayout("Insert Payload",payloadInsertPannel,0,0);

        JPanel insertPayloadPanel = buildInsertPayloadPanel();
        GridBagConstraints payloadInsertPannelConstraints = new GridBagConstraints();
        payloadInsertPannelConstraints.gridx = 0;
        payloadInsertPannelConstraints.gridy = 1;
        payloadInsertPannel.add(insertPayloadPanel,payloadInsertPannelConstraints);

        // 创建JSeparator组件
        JSeparator separator = new JSeparator(JSeparator.VERTICAL);
        GridBagConstraints separatorConstraints = new GridBagConstraints();
        separatorConstraints.gridx = 1;
        separatorConstraints.gridy = 0;
        separatorConstraints.fill = GridBagConstraints.VERTICAL;
        separatorConstraints.gridheight = GridBagConstraints.REMAINDER;
        separatorConstraints.weighty = 1.0;
        separatorConstraints.insets = new Insets(0,10,0,10);
        payloadInsertPannel.add(separator, separatorConstraints);

        // 创建JTextArea组件，并添加到一个JScrollPane中
        tipsArea = new JTextArea(10, 100);
        tipsShowAll();
        tipsArea.setEditable(false);
        JScrollPane tipsScrollPane = new JScrollPane(tipsArea);
        tipsScrollPane.setBorder(BorderFactory.createTitledBorder("Tips"));
        GridBagConstraints tipsScrollPaneConstraints = new GridBagConstraints();
        tipsScrollPaneConstraints.gridx = 2;
        tipsScrollPaneConstraints.gridy = 0;
        tipsScrollPaneConstraints.weighty = 1.0D;
        tipsScrollPaneConstraints.weightx = 1.0D;
        tipsScrollPaneConstraints.gridheight = GridBagConstraints.REMAINDER;
        tipsScrollPaneConstraints.gridwidth = GridBagConstraints.REMAINDER;
        //tipsScrollPaneConstraints.fill = GridBagConstraints.BOTH;
        tipsScrollPaneConstraints.insets = new Insets(0,0,0,10);
        payloadInsertPannel.add(tipsScrollPane, tipsScrollPaneConstraints);

        return  payloadInsertPannel;
    }

    public JPanel buildInsertPayloadPanel(){
        JPanel insertPayloadPanel = new JPanel();
        insertPayloadPanel.setLayout(new GridBagLayout());
        insertPayloadPanel.setBorder(BorderFactory.createRaisedBevelBorder());
        insertPayloadPanel.setBorder(BorderFactory.createLineBorder(Color.black));

        //Number选择panel
        JPanel numberPanel = new JPanel();
        numberPanel.setLayout(new GridBagLayout());
        //numberPanel.setBorder(BorderFactory.createTitledBorder("测试范围"));
        String []data = new String[updateNum];
        for(int i=0;i<updateNum;i++){
            data[i] = String.valueOf(i+1);
        }
        final JComboBox numberComboBox = new JComboBox(data);
        JLabel message = new JLabel("Number：");
        final JButton removeButton = new JButton("Remove");
        final JButton updateButton = new JButton("Update");
        GridBagConstraints numberPanelConstraints = new GridBagConstraints();
        numberPanelConstraints.ipady = 5;
        numberPanelConstraints.ipadx = 5;
        numberPanelConstraints.gridx = 0 ;
        numberPanelConstraints.gridy = 0;
        numberPanel.add(message,numberPanelConstraints);
        numberPanelConstraints.gridx = 1;
        numberPanel.add(numberComboBox,numberPanelConstraints);
        numberPanelConstraints.gridx = 2;
        numberPanelConstraints.insets = new Insets(0,20,0,0);
        numberPanel.add(removeButton,numberPanelConstraints);
        numberPanelConstraints.gridx = 3;
        numberPanelConstraints.insets = new Insets(0,0,0,0);
        numberPanel.add(updateButton,numberPanelConstraints);


        //其余
        JPanel payloadPanel = new JPanel();
        payloadPanel.setLayout(new GridBagLayout());
        payloadPanel.setBorder(BorderFactory.createLoweredBevelBorder());
        GridBagConstraints payloadPanelConstraints = new GridBagConstraints();
        //--第一组按钮
        addButton  = new JRadioButton (   "Add");
        coverButton = new JRadioButton (  "Cover");
        cleanButton = new JRadioButton ("Clean");
        methodButtonGroup = new ButtonGroup();methodButtonGroup.add(addButton);methodButtonGroup.add(coverButton);methodButtonGroup.add(cleanButton);
        JPanel jPanel1 = new JPanel();
        jPanel1.setLayout(new GridBagLayout());
        //jPanel1.setBorder(BorderFactory.createTitledBorder("测试范围"));
        GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
        gridBagConstraints1.insets = new Insets(0,0,0,30);
        gridBagConstraints1.gridx = 0 ;
        gridBagConstraints1.gridy = 0;
        gridBagConstraints1.gridwidth = 1;
        jPanel1.add(addButton,gridBagConstraints1);
        gridBagConstraints1.gridx = 1 ;
        jPanel1.add(coverButton,gridBagConstraints1);
        gridBagConstraints1.gridx = 2 ;
        jPanel1.add(cleanButton,gridBagConstraints1);
        //--第二组按钮
        headerButton = new JRadioButton ("Header");
        bodyButton = new JRadioButton (  "Body");
        pathButton = new JRadioButton (  "Path");
        paramButton = new JRadioButton(  "Param");
        positionButtonGroup = new ButtonGroup();positionButtonGroup.add(headerButton);positionButtonGroup.add(bodyButton);positionButtonGroup.add(pathButton);positionButtonGroup.add(paramButton);
        JPanel jPanel2 = new JPanel();
        jPanel2.setLayout(new GridBagLayout());
        GridBagConstraints gridBagConstraints2 = new GridBagConstraints();
        gridBagConstraints2.gridx = 0 ;
        gridBagConstraints2.gridy = 0;
        gridBagConstraints2.gridwidth = 1;
        gridBagConstraints2.insets = new Insets(0,0,0,30);
        jPanel2.add(headerButton,gridBagConstraints2);
        gridBagConstraints2.gridx = 1 ;
        jPanel2.add(bodyButton,gridBagConstraints2);
        gridBagConstraints2.gridx = 2 ;
        jPanel2.add(pathButton,gridBagConstraints2);
        gridBagConstraints2.gridx = 3;
        jPanel2.add(paramButton,gridBagConstraints2);
        innerButton = new JRadioButton ("Inner");
        outerButton = new JRadioButton ("Outer");
        inOrOutButtonGroup = new ButtonGroup();inOrOutButtonGroup.add(innerButton);inOrOutButtonGroup.add(outerButton);
        JPanel jPanel3 = new JPanel();
        jPanel3.setLayout(new GridBagLayout());
        GridBagConstraints gridBagConstraints3 = new GridBagConstraints();
        gridBagConstraints3.insets = new Insets(0,6,0,30);
        gridBagConstraints3.gridx = 0 ;
        gridBagConstraints3.gridy = 0;
        gridBagConstraints3.gridwidth = 1;
        jPanel3.add(innerButton,gridBagConstraints3);
        gridBagConstraints3.gridx = 1 ;
        jPanel3.add(outerButton,gridBagConstraints3);

        //--布局
        payloadPanelConstraints.gridx = 0;
        payloadPanelConstraints.gridy = 0;
        payloadPanelConstraints.weightx = 1.0D;
        payloadPanelConstraints.fill = GridBagConstraints.HORIZONTAL;
        payloadPanel.add(jPanel1,payloadPanelConstraints);
        //---分割线
        JSeparator payloadPanelSeparator1 = new JSeparator(0);
        this.callbacks.customizeUiComponent(payloadPanelSeparator1);
        GridBagConstraints payloadPanelSeparatorConstraints = new GridBagConstraints();
        payloadPanelSeparatorConstraints.gridx = 0;
        payloadPanelSeparatorConstraints.gridy = 1;
        payloadPanelSeparatorConstraints.gridwidth = 3;
        payloadPanelSeparatorConstraints.fill = GridBagConstraints.HORIZONTAL;
        payloadPanelSeparatorConstraints.anchor = GridBagConstraints.NORTH;
        payloadPanel.add(payloadPanelSeparator1, payloadPanelSeparatorConstraints);
        payloadPanelConstraints.gridy = 2;
        payloadPanel.add(jPanel2,payloadPanelConstraints);
        //--分割线
        JSeparator payloadPanelSeparator2 = new JSeparator(0);
        this.callbacks.customizeUiComponent(payloadPanelSeparator2);
        payloadPanelSeparatorConstraints.gridy = 3;
        payloadPanel.add(payloadPanelSeparator2, payloadPanelSeparatorConstraints);
        payloadPanelConstraints.gridy = 4;
        payloadPanel.add(jPanel3,payloadPanelConstraints);
        //--分割线
        JSeparator payloadPanelSeparator3 = new JSeparator(0);
        this.callbacks.customizeUiComponent(payloadPanelSeparator2);
        payloadPanelSeparatorConstraints.gridy = 5;
        payloadPanel.add(payloadPanelSeparator3, payloadPanelSeparatorConstraints);
        //--key字段
        JPanel keyPanel = new JPanel();
        keyPanel.setLayout(new GridBagLayout());
        JLabel keyLabel = new JLabel("Key：");
        keyText = new JTextField(30);
        keyPanel.add(keyLabel);
        keyPanel.add(keyText);
        payloadPanelSeparatorConstraints.gridx = 0;
        payloadPanelSeparatorConstraints.gridy = 6;
        payloadPanel.add(keyPanel,payloadPanelSeparatorConstraints);
        //--分割线
        JSeparator payloadPanelSeparator4 = new JSeparator(0);
        this.callbacks.customizeUiComponent(payloadPanelSeparator2);
        payloadPanelSeparatorConstraints.gridy = 7;
        payloadPanel.add(payloadPanelSeparator4, payloadPanelSeparatorConstraints);
        //--value字段
        final JPanel valuePanel = new JPanel();
        keyPanel.setLayout(new GridBagLayout());
        JLabel valueLabel = new JLabel("Val：");
        valueText = new JTextField(30);
        valuePanel.add(valueLabel);
        valuePanel.add(valueText);
        payloadPanelSeparatorConstraints.gridx = 0;
        payloadPanelSeparatorConstraints.gridy = 8;
        payloadPanel.add(valuePanel,payloadPanelSeparatorConstraints);


        GridBagConstraints insertPayloadPanelConstraints = new GridBagConstraints();
        insertPayloadPanelConstraints.gridx = 0;
        insertPayloadPanelConstraints.gridy = 0;
        insertPayloadPanel.add(numberPanel,insertPayloadPanelConstraints);
        insertPayloadPanelConstraints.gridy = 1;
        insertPayloadPanel.add(payloadPanel,insertPayloadPanelConstraints);



        /*设置所有监听器*/
        numberComboBox.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                boolean flag = true;
                if(e.SELECTED == e.getStateChange()){
                    //保存上一个数据并删除当前状态
                    if(methodButtonGroup.getSelection()!=null){
                        flag = false;
                        if(addButton.isSelected()) updateData[lastIndex].setMethod(UpdateData.PAYLOAD_ADD);
                        else if(coverButton.isSelected()) updateData[lastIndex].setMethod(UpdateData.PAYLOAD_COVER);
                        else if(cleanButton.isSelected()) updateData[lastIndex].setMethod(UpdateData.PAYLOAD_CLEAN);
                        methodButtonGroup.clearSelection();
                    }
                    if(positionButtonGroup.getSelection()!=null){
                        flag = false;
                        if(headerButton.isSelected()) updateData[lastIndex].setPosition(UpdateData.PAYLOAD_HEADER);
                        else if(bodyButton.isSelected()) updateData[lastIndex].setPosition(UpdateData.PAYLOAD_BODY);
                        else if(pathButton.isSelected()) updateData[lastIndex].setPosition(UpdateData.PAYLOAD_PATH);
                        else if(paramButton.isSelected()) updateData[lastIndex].setPosition(UpdateData.PAYLOAD_PARAM);
                        positionButtonGroup.clearSelection();
                    }
                    if(inOrOutButtonGroup.getSelection()!=null){
                        flag = false;
                        if(innerButton.isSelected()) updateData[lastIndex].setInOrOut(UpdateData.PAYLOAD_INNER);
                        else if(outerButton.isSelected()) updateData[lastIndex].setInOrOut(UpdateData.PAYLOAD_OUTER);
                        inOrOutButtonGroup.clearSelection();
                    }
                    updateData[lastIndex].setKeys(keyText.getText());keyText.setText("");
                    updateData[lastIndex].setValue(valueText.getText());valueText.setText("");
                    if(!flag) updateData[lastIndex].setIsNULL(flag);

                    //获取当前状态
                    lastIndex = Integer.parseInt((String) e.getItem())-1;
                    if(!updateData[lastIndex].getIsNULL()){
                        //method
                        if(updateData[lastIndex].getMthod() == UpdateData.PAYLOAD_ADD) addButton.setSelected(true);
                        else if(updateData[lastIndex].getMthod() == UpdateData.PAYLOAD_COVER) coverButton.setSelected(true);
                        else if(updateData[lastIndex].getMthod() == UpdateData.PAYLOAD_CLEAN) cleanButton.setSelected(true);
                        //position
                        if(updateData[lastIndex].getPosition() == UpdateData.PAYLOAD_HEADER) headerButton.setSelected(true);
                        else if(updateData[lastIndex].getPosition() == UpdateData.PAYLOAD_BODY) bodyButton.setSelected(true);
                        else if(updateData[lastIndex].getPosition() == UpdateData.PAYLOAD_PARAM) paramButton.setSelected(true);
                        else if(updateData[lastIndex].getPosition() == UpdateData.PAYLOAD_PATH) pathButton.setSelected(true);
                        //inOrOut
                        if(updateData[lastIndex].getInOrOut() == UpdateData.PAYLOAD_INNER) innerButton.setSelected(true);
                        else if(updateData[lastIndex].getInOrOut() == UpdateData.PAYLOAD_OUTER) outerButton.setSelected(true);
                        //key and value
                        keyText.setText(updateData[lastIndex].getKeys());
                        valueText.setText(updateData[lastIndex].getValue());
                    }
                    tipsShow();
                    updateButtonAvailability();
                }else if(e.DESELECTED == e.getStateChange()){
                    lastIndex = (Integer.parseInt((String) e.getItem())-1);
                }
            }
        });
        removeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                updateData[lastIndex].setMethod(-1);
                updateData[lastIndex].setPosition(-1);
                updateData[lastIndex].setInOrOut(-1);
                updateData[lastIndex].setKeys(null);
                updateData[lastIndex].setValue(null);
                updateData[lastIndex].setIsNULL(true);
                methodButtonGroup.clearSelection();
                positionButtonGroup.clearSelection();
                inOrOutButtonGroup.clearSelection();
                updateData[lastIndex].setKeys(keyText.getText());keyText.setText("");
                updateData[lastIndex].setValue(valueText.getText());valueText.setText("");
                tipsShow();
                updateButtonAvailability();
            }
        });
        updateButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                long startTime = System.currentTimeMillis();
                updateRequest();
                long endTime = System.currentTimeMillis();
                long elapsedTime = endTime - startTime;
                updateTable();
                System.out.println("修改完毕，执行时间："+elapsedTime);
            }
        });
        addButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                tipsShow();
                updateButtonAvailability();
            }
        });
        coverButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                tipsShow();
                updateButtonAvailability();
            }
        });
        cleanButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                tipsShow();
                updateButtonAvailability();
            }
        });
        headerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                tipsShow();
                updateButtonAvailability();
            }
        });
        bodyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                tipsShow();
                updateButtonAvailability();
            }
        });
        pathButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                tipsShow();
                updateButtonAvailability();
            }
        });
        paramButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                tipsShow();
                updateButtonAvailability();
            }
        });

        return insertPayloadPanel;
    }

    public JPanel buildJudgeSelectPanel(){
        JPanel judgeSelectPanel = new JPanel();
        judgeSelectPanel.setLayout(new GridBagLayout());
        GridBagConstraints judgeSelectConstraints = new GridBagConstraints();

        //添加标题
        this.addPanelTitleToGridBagLayout("Judge Method Select",judgeSelectPanel,0,0);

        //添加三个单选按钮
        JPanel radioButtonPanel = new JPanel();
        radioButtonPanel.setLayout(new GridBagLayout());
        stringJRadioButton = new JRadioButton("String");
        dnslogJRadioButton = new JRadioButton("Dnslog");
        serverJRadioButton = new JRadioButton("Server");
        timeJRadioButton = new JRadioButton("Time Delay");
        judgeSelect = new ButtonGroup();
        judgeSelect.add(stringJRadioButton);
        judgeSelect.add(dnslogJRadioButton);
        judgeSelect.add(serverJRadioButton);
        judgeSelect.add(timeJRadioButton);
        GridBagConstraints radioButtonPanelConstraints = new GridBagConstraints();
        radioButtonPanelConstraints.ipadx = 5;
        radioButtonPanelConstraints.ipady = 5;
        radioButtonPanelConstraints.gridx = 0;
        radioButtonPanelConstraints.gridy = 1;
        radioButtonPanelConstraints.gridwidth = 1;
        radioButtonPanel.add(stringJRadioButton,radioButtonPanelConstraints);
        radioButtonPanelConstraints.gridx = 1;
        radioButtonPanel.add(dnslogJRadioButton,radioButtonPanelConstraints);
        radioButtonPanelConstraints.gridx = 2;
        radioButtonPanel.add(serverJRadioButton,radioButtonPanelConstraints);
        radioButtonPanelConstraints.gridx = 3;
        radioButtonPanel.add(timeJRadioButton,radioButtonPanelConstraints);

        //填充物
        JPanel padding = new JPanel();

        //start按钮
        JButton startButton = new JButton("Start");
        startButton.addActionListener(e -> {
            if (!isStart.get()) { // 避免多次点击Start按钮
                isStart.set(true);
                isStopped.set(false);
                startButton.setEnabled(false);
                Thread thread = new Thread(() -> {
                    System.out.println("Start!!");
                    executor = Executors.newFixedThreadPool(6);
                    long startTime1 = System.currentTimeMillis();
                    for (RequestResponseClass requestresponseclass : hashMap.values().toArray(new RequestResponseClass[0])) {
                        if (!isStopped.get()) { // 判断是否点击了Stop按钮
                            executor.execute(() -> {
                                long startTime = System.currentTimeMillis();
                                // 在任务执行的过程中，检查中断状态
                                if (Thread.currentThread().isInterrupted()) {
                                    return; // 如果线程已经被中断，则立即停止任务
                                }
                                IHttpRequestResponse response = BurpExtender.this.callbacks.makeHttpRequest(requestresponseclass.getService(), requestresponseclass.getAfterRequest().getRequest());
                                long endTime = System.currentTimeMillis();
                                // 在任务执行的过程中，检查中断状态
                                if (Thread.currentThread().isInterrupted()) {
                                    return; // 如果线程已经被中断，则立即停止任务
                                }
                                requestresponseclass.getAfterRequest().setResponseTime((endTime - startTime) / 1000);
                                // 在任务执行的过程中，检查中断状态
                                if (Thread.currentThread().isInterrupted()) {
                                    return; // 如果线程已经被中断，则立即停止任务
                                }
                                requestresponseclass.getAfterRequest().setResponse(response);
                                // 在任务执行的过程中，检查中断状态
                                if (Thread.currentThread().isInterrupted()) {
                                    return; // 如果线程已经被中断，则立即停止任务
                                }
                                checkResult(requestresponseclass, response);
                            });
                        }
                    }
                    long endTime1 = System.currentTimeMillis();
                    long elapsedTime1 = endTime1 - startTime1;
                    System.out.println("测试完毕，执行时间："+elapsedTime1);
                    executor.shutdown();
                    try {
                        executor.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
                    } catch (InterruptedException ex) {
                        // handle
                    }

                    startButton.setEnabled(true);
                    isStart.set(false);
                    if(isStopped.get()){
                        return;
                    }
                    updateTable();
                    System.out.println("Finish!");
                });
                thread.start();
            }
        });

        //Stop按钮
        JButton stopButton = new JButton("Stop");
        stopButton.addActionListener(e -> {
            isStopped.set(true);
            if (executor != null) {
                executor.shutdownNow();
                try {
                    executor.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
                } catch (InterruptedException ex) {
                    // handle
                }
            }
            isStart.set(false);
            startButton.setEnabled(true); // Start按钮需要重新启用
            System.out.println("Stop!");
        });




        judgeSelectConstraints.gridx = 0;
        judgeSelectConstraints.gridy = 1;
        judgeSelectConstraints.ipadx = 10;
        judgeSelectConstraints.ipady = 10;
        judgeSelectConstraints.gridwidth = 1;
        judgeSelectPanel.add(radioButtonPanel,judgeSelectConstraints);
        judgeSelectConstraints.gridx = 1;
        judgeSelectConstraints.fill = GridBagConstraints.HORIZONTAL;
        judgeSelectConstraints.weightx = 1.0D;
        judgeSelectPanel.add(padding,judgeSelectConstraints);
        judgeSelectConstraints.gridx = 2;
        judgeSelectConstraints.weightx = 0.0;
        judgeSelectConstraints.fill = GridBagConstraints.NONE;
        judgeSelectPanel.add(stopButton,judgeSelectConstraints);
        judgeSelectConstraints.gridx = 3;
        judgeSelectPanel.add(startButton,judgeSelectConstraints);

        return judgeSelectPanel;
    }

    public void checkResult(RequestResponseClass requestresponseclass, IHttpRequestResponse response)  {//判断器 TODO
        if(response.getResponse()==null){
            requestresponseclass.setResult("Time out");
        }else {
            if (stringJRadioButton.isSelected()) {
                if (judgeText!=null&&!judgeText.equals("")) {
                    String text = helpers.bytesToString(response.getResponse());
                    String pattern = judgeText;
                    Pattern p = Pattern.compile(pattern);
                    Matcher m = p.matcher(text);
                    if (m.find()) {
                        requestresponseclass.setResult("Success");
                    } else {
                        requestresponseclass.setResult("Failure");
                    }
                } else {
                    System.out.println("请输入被匹配的判断字符串！");
                }
            } else if (dnslogJRadioButton.isSelected()) {//TODO
                //https://www.secpulse.com/archives/192081.html
                //http://ceye.io/introduce  dnsDomain:fpz8if.ceye.io  Token:17f5ead62c758aac4f8e99a7d4ab4eb3
                try{
                    if(ceyeToken.getText()!=null) {
                        String token = ceyeToken.getText();
                        String type = "dns";
                        String filter = String.valueOf(requestresponseclass.getHashcode());

                        String ceyeTestUrl = "http://api.ceye.io/v1/records?token=" + token + "&type=" + type + "&filter=" + filter;
                        URL ceyeURL = new URL(ceyeTestUrl);
                        URLConnection ceyeURLConnection = ceyeURL.openConnection();
                        //返回包的数据格式为json格式，进行获取并转换成json类
                        BufferedReader reader = new BufferedReader(new InputStreamReader(ceyeURLConnection.getInputStream()));
                        StringBuffer ceyeContent = new StringBuffer();
                        String line;
                        while ((line = reader.readLine()) != null) {
                            ceyeContent.append(line);
                        }
                        reader.close();
                        String ceyeJson = ceyeContent.toString();
                        JSONObject ceyeData = JSON.parseObject(ceyeJson);
                        if(JSON.parseArray(ceyeData.get("data").toString()).size()>0){
                            requestresponseclass.setResult("Success");
                        }else{
                            requestresponseclass.setResult("Failure");
                        }
                    }else{
                        System.out.println("ceye Token not NULL!");
                    }
                } catch (MalformedURLException e) {
                    requestresponseclass.setResult("Ceye Time out");
                    e.printStackTrace();
                } catch (IOException e) {
                    requestresponseclass.setResult("Ceye Time out");
                    e.printStackTrace();
                }

            } else if (serverJRadioButton.isSelected()) {
                String filter = String.valueOf(requestresponseclass.getHashcode());
                String fileName = BurpExtender.this.fileName.getText();
                String filePort = BurpExtender.this.filePort.getText();
                String serverIp = BurpExtender.this.serverIp.getText();

                try {
                    String fileUrl = "http://" + serverIp + ":" + filePort + "/" + fileName;
                    URL ceyeURL = new URL(fileUrl);
                    URLConnection ceyeURLConnection = ceyeURL.openConnection();
                    //返回包的数据格式为json格式，进行获取并转换成json类
                    BufferedReader reader = new BufferedReader(new InputStreamReader(ceyeURLConnection.getInputStream()));
                    StringBuffer fileContent = new StringBuffer();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        fileContent.append(line);
                    }
                    reader.close();
                    String serverFileContent = fileContent.toString();

                    Pattern p = Pattern.compile(filter);
                    Matcher m = p.matcher(serverFileContent);
                    if (m.find()) {
                        requestresponseclass.setResult("Success");
                    } else {
                        requestresponseclass.setResult("Failure");
                    }
                } catch (Exception e) {
                    requestresponseclass.setResult("Error");
                    e.printStackTrace();
                }

            }else if(timeJRadioButton.isSelected()){
                try {
                    System.out.println(requestresponseclass.getHashcode() +" : "+ requestresponseclass.getAfterRequest().getResponseTime());
                    if (requestresponseclass.getAfterRequest().getResponseTime() >= Integer.valueOf(timeNum.getText())){
                        requestresponseclass.setResult("Success");
                    }else{
                        requestresponseclass.setResult("Failure");
                    }
                }catch (Exception e){
                    System.out.println("timeNum must be Number");
                }
            }
            else{
                System.out.println("Please select the judge method.");
            }
        }

    }

    private JLabel addPanelTitleToGridBagLayout(String titleText, Container gridBagContainer,int xPosition, int yPosition) {
        JLabel panelTitle = new JLabel(titleText, 2);
        panelTitle.setForeground(new Color(236, 136, 0));
        Font font = panelTitle.getFont();
        panelTitle.setFont(new Font(font.getFontName(), font.getStyle(), font.getSize() + 4));
        panelTitle.setHorizontalAlignment(2);
        this.callbacks.customizeUiComponent(panelTitle);
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridwidth = 3;
        gridBagConstraints.gridx = xPosition;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        gridBagConstraints.fill = 2;
        gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
        gridBagContainer.add(panelTitle, gridBagConstraints);
        return panelTitle;
    }

    private void updateRequest(){
        /*用户体验*/
        //保存最后一次切Nunber时的所需做出修改的数据
        boolean flag = true;
        if(methodButtonGroup.getSelection()!=null){
            flag = false;
            if(addButton.isSelected()) updateData[lastIndex].setMethod(UpdateData.PAYLOAD_ADD);
            else if(coverButton.isSelected()) updateData[lastIndex].setMethod(UpdateData.PAYLOAD_COVER);
            else if(cleanButton.isSelected()) updateData[lastIndex].setMethod(UpdateData.PAYLOAD_CLEAN);
        }
        if(positionButtonGroup.getSelection()!=null){
            flag = false;
            if(headerButton.isSelected()) updateData[lastIndex].setPosition(UpdateData.PAYLOAD_HEADER);
            else if(bodyButton.isSelected()) updateData[lastIndex].setPosition(UpdateData.PAYLOAD_BODY);
            else if(pathButton.isSelected()) updateData[lastIndex].setPosition(UpdateData.PAYLOAD_PATH);
            else if(paramButton.isSelected()) updateData[lastIndex].setPosition(UpdateData.PAYLOAD_PARAM);
        }
        if(inOrOutButtonGroup.getSelection()!=null){
            flag = false;
            if(innerButton.isSelected()) updateData[lastIndex].setInOrOut(UpdateData.PAYLOAD_INNER);
            else if(outerButton.isSelected()) updateData[lastIndex].setInOrOut(UpdateData.PAYLOAD_OUTER);
        }
        updateData[lastIndex].setKeys(keyText.getText());
        updateData[lastIndex].setValue(valueText.getText());
        if(!flag) updateData[lastIndex].setIsNULL(flag);


        //更新功能
        for(UpdateData updateData:updateData){
            if(!updateData.getIsNULL()){
                for(RequestResponseClass requestresponseclass:hashMap.values()){
                    if(!requestresponseclass.getUpdate()){
                        requestresponseclass.resetAfterRequest();
                        requestresponseclass.setUpdateTrue();
                    }
                    if(dnslogJRadioButton.isSelected()){
                        if(ceyeDnsDomain.getText()!=null){//只有ceyeDnsDomain不为空且dnslog按钮被选择，才会在update的时候替换${ceyeDnsDomain}
                            requestresponseclass.getAfterRequest().modifyrequest(updateData.getMthod(),updateData.getPosition(),updateData.getInOrOut(),updateData.getKeys(),updateData.getValue().replace("${ceyeDnsDomain}",requestresponseclass.getHashcode()+"."+ceyeDnsDomain.getText()));
                        }else{
                            System.out.println("cyce dnsDomain is not NULL！");
                        }
                    }else if(serverJRadioButton.isSelected()){
                        if(serverIp.getText()!=null&&serverPort.getText()!=null){
                            requestresponseclass.getAfterRequest().modifyrequest(updateData.getMthod(),updateData.getPosition(),updateData.getInOrOut(),updateData.getKeys(),updateData.getValue().replace("${serverIp}",serverIp.getText()).replace("${serverPort}",serverPort.getText()).replace("${replace}",requestresponseclass.getHashcode()+""));
                        }else{
                            System.out.println("serverIp or serverPort is not NULL！");
                        }
                    }
                    else{
                        requestresponseclass.getAfterRequest().modifyrequest(updateData.getMthod(),updateData.getPosition(),updateData.getInOrOut(),updateData.getKeys(),updateData.getValue());
                    }
                }
            }
        }
        for(RequestResponseClass requestresponseclass:hashMap.values()){
            requestresponseclass.getAfterRequest().reBuildRequest();
            requestresponseclass.setUpdateFalse();
        }

//        //及时更新面板呈现的数据i
//        int row = BurpExtender.this.displayTable.getSelectedRow();
//        if(row != -1){//getBeforeRequestText
//            Object hashid = BurpExtender.this.displayTable.getValueAt(row,0);
//            beforeRequestText.setText(hashMap.get(Integer.parseInt(String.valueOf(hashid))).getBeforeRequestText());
//            afterRequestText.setText(hashMap.get(Integer.parseInt(String.valueOf(hashid))).getAfterRequestText());
//            BurpExtender.this.displayTable.setRowSelectionInterval(row,row);
//        }
    }

    private void updateTable(){
        //清除表中的数据
        if (tableData.getRowCount() > 0) {
            for (int i = tableData.getRowCount() - 1; i > -1; i--) {
                tableData.removeRow(i);
            }
        }
        //重新展示新的数据
        for(RequestResponseClass requestresponseclass:hashMap.values()){
            if(requestresponseclass!=null){
                tableData.addRow(new String[]{String.valueOf(requestresponseclass.getHashcode()), requestresponseclass.getHost(), requestresponseclass.getMethod(),requestresponseclass.getUrl(), requestresponseclass.getStatus(), requestresponseclass.getLength(), requestresponseclass.getMime(), requestresponseclass.getPort(), requestresponseclass.getCookies(), requestresponseclass.getResult()});
            }
        }
    }

    private void tipsShow(){
        if(addButton.isSelected()){
            if(headerButton.isSelected()){
                tipsArea.setText("Header位置：  添加字段到请求头\n" +
                        "    Inner内部插：{\n" +
                        "        解释：添加到某个字段内，key前加 某个字段+\":\" 即可表示加在哪个字段里面。如果未存在外部字段，重新构造字段加入head。最多支持两层\"key1:key2\"\n" +
                        "        key值格式： \"外层字段名:内层字段名\"\n" +
                        "        value值格式：无\n" +
                        "        例子：key值=\"Cookie:name\",value值=\"456\"，此时\"Cookie:name\"被分割成Cookie和name\n" +
                        "        Cookie: name=123 \n" +
                        "        修改成\n" +
                        "        Cookie: name=123(保留)\n" +
                        "        Cookie:name=456\n" +
                        "    }\n" +
                        "    Outer外部插：{\n" +
                        "        解释：直接添加到头的最尾部,距离Body最近的位置\n" +
                        "        key值格式： 无\n" +
                        "        value值格式：无\n" +
                        "        例子：key值=\"Cookie:name\",value值=\"456\",此时\"Cookie:name\"是整个的字段\n" +
                        "        Cookie: name=123 \n" +
                        "        修改成\n" +
                        "        Cookie: name=123(保留)\n" +
                        "        Cookie:name:456\n" +
                        "    }");
            }else if(pathButton.isSelected()){
                tipsArea.setText("Path位置：添加value值到路径中\n" +
                        "    Inner：无\n" +
                        "    Outer：无\n" +
                        "    {\n" +
                        "        解释：在Add功能中，以路径/a/b/c/为例，value注入的位置被划分为0 /a 1 /b 2 /c 3，key值必须为数字，表示插入到路径的哪个地方，\n" +
                        "             同时如果key值小于0则默认加在路径最前面，超过最大位置数的，默认加在路径最后面\n" +
                        "        key值格式：必须数字\n" +
                        "        value值格式：无\n" +
                        "        例子：key值=\"2\",value值=\"d\"\n" +
                        "        /a/b/c/\n" +
                        "        修改成\n" +
                        "        /a/b/d/c\n" +
                        "    }");
            }else if(paramButton.isSelected()){
                tipsArea.setText("Param位置：添加字段到Get参数\n" +
                        "    Inner头插：{\n" +
                        "        解释：直接添加字段到参数的最前面\n" +
                        "        key值格式：无\n" +
                        "        value值格式：无\n" +
                        "        例子： key值=\"id1\",value值=\"3\"\n" +
                        "        /a/b/c?id1=1&id2=2\n" +
                        "        修改成\n" +
                        "        /a/b/c?id1=3&id1=1&id2=2\n" +
                        "    }\n" +
                        "    Outer尾插：{\n" +
                        "        解释：直接添加字段到参数的最后面\n" +
                        "        key值格式：无\n" +
                        "        value值格式：无\n" +
                        "        例子： key值=\"id1\",value值=\"3\"\n" +
                        "        /a/b/c?id1=1&id2=2\n" +
                        "        修改成\n" +
                        "        /a/b/c?id1=1&id2=2&id1=3\n" +
                        "    }");
            }else if(bodyButton.isSelected()){
                tipsArea.setText("Body位置：支持application/x-www-form-urlencoded、multipart/form-data,application/json、application/xml和text/xml仅被Clean功能支持\n" +
                        "    application/x-www-form-urlencoded： url编码，默认是参数结构 a=b&c=d\n" +
                        "        Inner头插：{\n" +
                        "            解释：类似GET参数插入，直接添加到参数的最前面\n" +
                        "            key值格式：无\n" +
                        "            value值格式：无\n" +
                        "            例子： key值=\"id1\",value值=\"3\"\n" +
                        "            id1=1&id2=2\n" +
                        "            修改成\n" +
                        "            id1=3&id1=1&id2=2\n" +
                        "        }\n" +
                        "        Outer尾插：{\n" +
                        "            解释：类似GET参数插入，直接添加到参数的最后面\n" +
                        "            key值格式：无\n" +
                        "            value值格式：无\n" +
                        "            例子： key值=\"id1\",value值=\"3\"\n" +
                        "            id1=1&id2=2\n" +
                        "            修改成\n" +
                        "            id1=1&id2=2&id1=3\n" +
                        "        }\n" +
                        "    multipart/form-data： 支持文件格式、表格格式(用户名和密码)\n" +
                        "        文件格式：\n" +
                        "            Inner头插：{\n" +
                        "                解释：添加到数据序列最前面\n" +
                        "                key值格式： name:filename:Content-Type\n" +
                        "                value值格式：无\n" +
                        "                例子： key值=\"file1:file2:text/plain\",value值=\"3\"\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                Content-Disposition: form-data; name=\"file\"; filename=\"xxx.txt\"\n" +
                        "                Content-Type: text/plain\n" +
                        "\n" +
                        "                xxxxxx\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                修改成\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                Content-Disposition: form-data; name=\"file1\"; filename=\"file2\"\n" +
                        "                Content-Type: text/plain\n" +
                        "\n" +
                        "                3\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                Content-Disposition: form-data; name=\"file\"; filename=\"xxx.txt\"\n" +
                        "                Content-Type: text/plain\n" +
                        "\n" +
                        "                xxxxxx\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "            }\n" +
                        "            Outer尾插：{\n" +
                        "                解释：添加到数据序列最后面\n" +
                        "                key值格式： name:filename:Content-Type\n" +
                        "                value值格式：无\n" +
                        "                例子： key值=\"file1:file2:text/plain\",value值=\"3\"\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                Content-Disposition: form-data; name=\"file\"; filename=\"xxx.txt\"\n" +
                        "                Content-Type: text/plain\n" +
                        "\n" +
                        "                xxxxxx\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                修改成\n" +
                        "            \n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                Content-Disposition: form-data; name=\"file\"; filename=\"xxx.txt\"\n" +
                        "                Content-Type: text/plain\n" +
                        "\n" +
                        "                xxxxxx\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                Content-Disposition: form-data; name=\"file1\"; filename=\"file2\"\n" +
                        "                Content-Type: text/plain\n" +
                        "\n" +
                        "                3\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "            }\n" +
                        "        表格格式：\n" +
                        "            Inner头插：{\n" +
                        "                解释：添加到数据序列最前面\n" +
                        "                key值格式： name:null(不变):null(不变)\n" +
                        "                value值格式：无\n" +
                        "                例子： key值=\"name1:null:null\",value值=\"3\"\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                Content-Disposition: form-data; name=\"name1\"\n" +
                        "\n" +
                        "                xxxx\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                修改成\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                Content-Disposition: form-data; name=\"name1\"\n" +
                        "\n" +
                        "                3\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                Content-Disposition: form-data; name=\"name1\"\n" +
                        "\n" +
                        "                xxxx\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "            }\n" +
                        "            Outer尾插：{\n" +
                        "                解释：添加到数据序列最后面\n" +
                        "                key值格式： name:null(不变):null(不变)\n" +
                        "                value值格式：无\n" +
                        "                例子： key值=\"file1:null:null\",value值=\"3\"\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                Content-Disposition: form-data; name=\"name1\"\n" +
                        "\n" +
                        "                xxxx\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                修改成\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                Content-Disposition: form-data; name=\"name1\"\n" +
                        "\n" +
                        "                xxxx\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                Content-Disposition: form-data; name=\"name1\"\n" +
                        "\n" +
                        "                3\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "            }");
            }else{
                tipsArea.setText("Add功能：  添加字段，不覆盖已有同名字段\n" +
                        "    Header位置：  添加字段到请求头\n" +
                        "        Inner内部插：{\n" +
                        "            解释：添加到某个字段内，key前加 某个字段+\":\" 即可表示加在哪个字段里面。如果未存在外部字段，重新构造字段加入head。最多支持两层\"key1:key2\"\n" +
                        "            key值格式： \"外层字段名:内层字段名\"\n" +
                        "            value值格式：无\n" +
                        "            例子：key值=\"Cookie:name\",value值=\"456\"，此时\"Cookie:name\"被分割成Cookie和name\n" +
                        "            Cookie: name=123 \n" +
                        "            修改成\n" +
                        "            Cookie: name=123(保留)\n" +
                        "            Cookie:name=456\n" +
                        "        }\n" +
                        "        Outer外部插：{\n" +
                        "            解释：直接添加到头的最尾部,距离Body最近的位置\n" +
                        "            key值格式： 无\n" +
                        "            value值格式：无\n" +
                        "            例子：key值=\"Cookie:name\",value值=\"456\",此时\"Cookie:name\"是整个的字段\n" +
                        "            Cookie: name=123 \n" +
                        "            修改成\n" +
                        "            Cookie: name=123(保留)\n" +
                        "            Cookie:name:456\n" +
                        "        }\n" +
                        "    Path位置：添加value值到路径中\n" +
                        "        Inner：无\n" +
                        "        Outer：无\n" +
                        "        {\n" +
                        "            解释：在Add功能中，以路径/a/b/c/为例，value注入的位置被划分为0 /a 1 /b 2 /c 3，key值必须为数字，表示插入到路径的哪个地方，\n" +
                        "                 同时如果key值小于0则默认加在路径最前面，超过最大位置数的，默认加在路径最后面\n" +
                        "            key值格式：必须数字\n" +
                        "            value值格式：无\n" +
                        "            例子：key值=\"2\",value值=\"d\"\n" +
                        "            /a/b/c/\n" +
                        "            修改成\n" +
                        "            /a/b/d/c\n" +
                        "        }\n" +
                        "    Param位置：添加字段到Get参数\n" +
                        "        Inner头插：{\n" +
                        "            解释：直接添加字段到参数的最前面\n" +
                        "            key值格式：无\n" +
                        "            value值格式：无\n" +
                        "            例子： key值=\"id1\",value值=\"3\"\n" +
                        "            /a/b/c?id1=1&id2=2\n" +
                        "            修改成\n" +
                        "            /a/b/c?id1=3&id1=1&id2=2\n" +
                        "        }\n" +
                        "        Outer尾插：{\n" +
                        "            解释：直接添加字段到参数的最后面\n" +
                        "            key值格式：无\n" +
                        "            value值格式：无\n" +
                        "            例子： key值=\"id1\",value值=\"3\"\n" +
                        "            /a/b/c?id1=1&id2=2\n" +
                        "            修改成\n" +
                        "            /a/b/c?id1=1&id2=2&id1=3\n" +
                        "        }\n" +
                        "    Body位置：支持application/x-www-form-urlencoded、multipart/form-data,application/json、application/xml和text/xml仅被Clean功能支持\n" +
                        "        application/x-www-form-urlencoded： url编码，默认是参数结构 a=b&c=d\n" +
                        "            Inner头插：{\n" +
                        "                解释：类似GET参数插入，直接添加到参数的最前面\n" +
                        "                key值格式：无\n" +
                        "                value值格式：无\n" +
                        "                例子： key值=\"id1\",value值=\"3\"\n" +
                        "                id1=1&id2=2\n" +
                        "                修改成\n" +
                        "                id1=3&id1=1&id2=2\n" +
                        "            }\n" +
                        "            Outer尾插：{\n" +
                        "                解释：类似GET参数插入，直接添加到参数的最后面\n" +
                        "                key值格式：无\n" +
                        "                value值格式：无\n" +
                        "                例子： key值=\"id1\",value值=\"3\"\n" +
                        "                id1=1&id2=2\n" +
                        "                修改成\n" +
                        "                id1=1&id2=2&id1=3\n" +
                        "            }\n" +
                        "        multipart/form-data： 支持文件格式、表格格式(用户名和密码)\n" +
                        "            文件格式：\n" +
                        "                Inner头插：{\n" +
                        "                    解释：添加到数据序列最前面\n" +
                        "                    key值格式： name:filename:Content-Type\n" +
                        "                    value值格式：无\n" +
                        "                    例子： key值=\"file1:file2:text/plain\",value值=\"3\"\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    Content-Disposition: form-data; name=\"file\"; filename=\"xxx.txt\"\n" +
                        "                    Content-Type: text/plain\n" +
                        "\n" +
                        "                    xxxxxx\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    修改成\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    Content-Disposition: form-data; name=\"file1\"; filename=\"file2\"\n" +
                        "                    Content-Type: text/plain\n" +
                        "\n" +
                        "                    3\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    Content-Disposition: form-data; name=\"file\"; filename=\"xxx.txt\"\n" +
                        "                    Content-Type: text/plain\n" +
                        "\n" +
                        "                    xxxxxx\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                }\n" +
                        "                Outer尾插：{\n" +
                        "                    解释：添加到数据序列最后面\n" +
                        "                    key值格式： name:filename:Content-Type\n" +
                        "                    value值格式：无\n" +
                        "                    例子： key值=\"file1:file2:text/plain\",value值=\"3\"\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    Content-Disposition: form-data; name=\"file\"; filename=\"xxx.txt\"\n" +
                        "                    Content-Type: text/plain\n" +
                        "\n" +
                        "                    xxxxxx\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    修改成\n" +
                        "                \n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    Content-Disposition: form-data; name=\"file\"; filename=\"xxx.txt\"\n" +
                        "                    Content-Type: text/plain\n" +
                        "\n" +
                        "                    xxxxxx\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    Content-Disposition: form-data; name=\"file1\"; filename=\"file2\"\n" +
                        "                    Content-Type: text/plain\n" +
                        "\n" +
                        "                    3\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                }\n" +
                        "            表格格式：\n" +
                        "                Inner头插：{\n" +
                        "                    解释：添加到数据序列最前面\n" +
                        "                    key值格式： name:null(不变):null(不变)\n" +
                        "                    value值格式：无\n" +
                        "                    例子： key值=\"name1:null:null\",value值=\"3\"\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    Content-Disposition: form-data; name=\"name1\"\n" +
                        "\n" +
                        "                    xxxx\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    修改成\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    Content-Disposition: form-data; name=\"name1\"\n" +
                        "\n" +
                        "                    3\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    Content-Disposition: form-data; name=\"name1\"\n" +
                        "\n" +
                        "                    xxxx\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                }\n" +
                        "                Outer尾插：{\n" +
                        "                    解释：添加到数据序列最后面\n" +
                        "                    key值格式： name:null(不变):null(不变)\n" +
                        "                    value值格式：无\n" +
                        "                    例子： key值=\"file1:null:null\",value值=\"3\"\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    Content-Disposition: form-data; name=\"name1\"\n" +
                        "\n" +
                        "                    xxxx\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    修改成\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    Content-Disposition: form-data; name=\"name1\"\n" +
                        "\n" +
                        "                    xxxx\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    Content-Disposition: form-data; name=\"name1\"\n" +
                        "\n" +
                        "                    3\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                }");
            }
        }
        else if(coverButton.isSelected()){
            if(headerButton.isSelected()){
                tipsArea.setText("Header位置：  覆盖请求头同名字段，若字段不存在，则默认添加上去\n" +
                        "    Inner内部插：{\n" +
                        "        解释：覆盖到某个外部字段内的同名内部字段，若外部字段活内部字段不存在，则添加上去。key前加 某个字段+\":\" 即可表示加在哪个外部字段里面。\n" +
                        "             如果未存在外部字段，重新构造字段加入head。最多支持两层\"key1:key2\"\n" +
                        "        key值格式： \"外层字段名:内层字段名\"\n" +
                        "        value值格式：无\n" +
                        "        例子：key值=\"Cookie:name\",value值=\"456\"，此时\"Cookie:name\"被分割成Cookie和name\n" +
                        "        Cookie: name=123 \n" +
                        "        修改成\n" +
                        "        Cookie: name=456\n" +
                        "    }\n" +
                        "    Outer外部插：{\n" +
                        "        解释：直接添加到头的最尾部,距离Body最近的位置\n" +
                        "        key值格式： 无\n" +
                        "        value值格式：无\n" +
                        "        例子：key值=\"Cookie:name\",value值=\"456\",此时\"Cookie:name\"是整个的字段\n" +
                        "        Cookie: name=123 \n" +
                        "        修改成\n" +
                        "        Cookie: name=123\n" +
                        "        Cookie:name:456\n" +
                        "    }");
            }else if(pathButton.isSelected()){
                tipsArea.setText("Path位置：   覆盖路径的某个子路径，由key指定\n" +
                        "    Inner：无\n" +
                        "    Outer：无\n" +
                        "    {\n" +
                        "        解释：在Cover功能中，以路径/a/b/c/为例，value注入的位置被划分为/a(0) /b(1) /c(2)，key值必须为数字，表示覆盖路径的哪个部分，\n" +
                        "             同时如果key值小于0则默认覆盖路径最前面部分，比如0位置，超过最大位置数的，默认覆盖路径最后面部分，比如2位置\n" +
                        "        key值格式：必须数字\n" +
                        "        value值格式：无\n" +
                        "        例子：key值=\"2\",value值=\"d\"\n" +
                        "        /a/b/c/\n" +
                        "        修改成\n" +
                        "        /a/d/c\n" +
                        "    }");
            }else if(paramButton.isSelected()){
                tipsArea.setText("Param位置：   覆盖Get参数同名字段 \n" +
                        "    Inner：无\n" +
                        "    Outer：无\n" +
                        "    {\n" +
                        "        解释：直接覆盖同名字段，若不存在则默认加在参数的最后面\n" +
                        "        key值格式：无\n" +
                        "        value值格式：无\n" +
                        "        例子： key值=\"id1\",value值=\"3\"\n" +
                        "        /a/b/c?id1=1&id2=2\n" +
                        "        修改成\n" +
                        "        /a/b/c?id1=3&id2=2\n" +
                        "    }");
            }else if(bodyButton.isSelected()){
                tipsArea.setText("Body位置：   支持application/x-www-form-urlencoded、multipart/form-data\n" +
                        "    application/x-www-form-urlencoded：\n" +
                        "        Inner：无\n" +
                        "        Outer：无\n" +
                        "        {\n" +
                        "            解释：类似GET参数覆盖，覆盖同名字段，若不存在，则添加到参数的最后面\n" +
                        "            key值格式：无\n" +
                        "            value值格式：无\n" +
                        "            例子： key值=\"id1\",value值=\"3\"\n" +
                        "            id1=1&id2=2\n" +
                        "            修改成\n" +
                        "            id1=3&id2=2\n" +
                        "        }\n" +
                        "    multipart/form-data：\n" +
                        "        文件格式：\n" +
                        "            Inner：无\n" +
                        "            Outer：无\n" +
                        "            {\n" +
                        "                解释：覆盖同name、同filename、同Content-type的数据段，若无匹配则添加到数据序列最后面\n" +
                        "                key值格式： name:filename:Content-Type\n" +
                        "                value值格式：无\n" +
                        "                例子： key值=\"file:xxx.txt:text/plain\",value值=\"3\"\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                Content-Disposition: form-data; name=\"file\"; filename=\"xxx.txt\"\n" +
                        "                Content-Type: text/plain\n" +
                        "\n" +
                        "                xxxxxx\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                修改成\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                Content-Disposition: form-data; name=\"file\"; filename=\"xxx.txt\"\n" +
                        "                Content-Type: text/plain\n" +
                        "\n" +
                        "                3\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "            }\n" +
                        "        表格格式：\n" +
                        "            Inner：无\n" +
                        "            Outer：无\n" +
                        "            {\n" +
                        "                解释：覆盖同name的数据段，若不存在则添加到数据序列最后面\n" +
                        "                key值格式： name:null(不变):null(不变)\n" +
                        "                value值格式：无\n" +
                        "                例子： key值=\"name1:null:null\",value值=\"3\"\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                Content-Disposition: form-data; name=\"name1\"\n" +
                        "\n" +
                        "                xxxx\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                修改成\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                Content-Disposition: form-data; name=\"name1\"\n" +
                        "\n" +
                        "                3\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "            }");
            }else{
                tipsArea.setText("Cover功能：  覆盖同名字段\n" +
                        "    Header位置：  覆盖请求头同名字段，若字段不存在，则默认添加上去\n" +
                        "        Inner内部插：{\n" +
                        "            解释：覆盖到某个外部字段内的同名内部字段，若外部字段活内部字段不存在，则添加上去。key前加 某个字段+\":\" 即可表示加在哪个外部字段里面。\n" +
                        "                 如果未存在外部字段，重新构造字段加入head。最多支持两层\"key1:key2\"\n" +
                        "            key值格式： \"外层字段名:内层字段名\"\n" +
                        "            value值格式：无\n" +
                        "            例子：key值=\"Cookie:name\",value值=\"456\"，此时\"Cookie:name\"被分割成Cookie和name\n" +
                        "            Cookie: name=123 \n" +
                        "            修改成\n" +
                        "            Cookie: name=456\n" +
                        "        }\n" +
                        "        Outer外部插：{\n" +
                        "            解释：直接添加到头的最尾部,距离Body最近的位置\n" +
                        "            key值格式： 无\n" +
                        "            value值格式：无\n" +
                        "            例子：key值=\"Cookie:name\",value值=\"456\",此时\"Cookie:name\"是整个的字段\n" +
                        "            Cookie: name=123 \n" +
                        "            修改成\n" +
                        "            Cookie: name=123\n" +
                        "            Cookie:name:456\n" +
                        "        }\n" +
                        "    Path位置：   覆盖路径的某个子路径，由key指定\n" +
                        "        Inner：无\n" +
                        "        Outer：无\n" +
                        "        {\n" +
                        "            解释：在Cover功能中，以路径/a/b/c/为例，value注入的位置被划分为/a(0) /b(1) /c(2)，key值必须为数字，表示覆盖路径的哪个部分，\n" +
                        "                 同时如果key值小于0则默认覆盖路径最前面部分，比如0位置，超过最大位置数的，默认覆盖路径最后面部分，比如2位置\n" +
                        "            key值格式：必须数字\n" +
                        "            value值格式：无\n" +
                        "            例子：key值=\"2\",value值=\"d\"\n" +
                        "            /a/b/c/\n" +
                        "            修改成\n" +
                        "            /a/d/c\n" +
                        "        }\n" +
                        "    Param位置：   覆盖Get参数同名字段 \n" +
                        "        Inner：无\n" +
                        "        Outer：无\n" +
                        "        {\n" +
                        "            解释：直接覆盖同名字段，若不存在则默认加在参数的最后面\n" +
                        "            key值格式：无\n" +
                        "            value值格式：无\n" +
                        "            例子： key值=\"id1\",value值=\"3\"\n" +
                        "            /a/b/c?id1=1&id2=2\n" +
                        "            修改成\n" +
                        "            /a/b/c?id1=3&id2=2\n" +
                        "        }\n" +
                        "    Body位置：   支持application/x-www-form-urlencoded、multipart/form-data\n" +
                        "        application/x-www-form-urlencoded：\n" +
                        "            Inner：无\n" +
                        "            Outer：无\n" +
                        "            {\n" +
                        "                解释：类似GET参数覆盖，覆盖同名字段，若不存在，则添加到参数的最后面\n" +
                        "                key值格式：无\n" +
                        "                value值格式：无\n" +
                        "                例子： key值=\"id1\",value值=\"3\"\n" +
                        "                id1=1&id2=2\n" +
                        "                修改成\n" +
                        "                id1=3&id2=2\n" +
                        "            }\n" +
                        "        multipart/form-data：\n" +
                        "            文件格式：\n" +
                        "                Inner：无\n" +
                        "                Outer：无\n" +
                        "                {\n" +
                        "                    解释：覆盖同name、同filename、同Content-type的数据段，若无匹配则添加到数据序列最后面\n" +
                        "                    key值格式： name:filename:Content-Type\n" +
                        "                    value值格式：无\n" +
                        "                    例子： key值=\"file:xxx.txt:text/plain\",value值=\"3\"\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    Content-Disposition: form-data; name=\"file\"; filename=\"xxx.txt\"\n" +
                        "                    Content-Type: text/plain\n" +
                        "\n" +
                        "                    xxxxxx\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    修改成\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    Content-Disposition: form-data; name=\"file\"; filename=\"xxx.txt\"\n" +
                        "                    Content-Type: text/plain\n" +
                        "\n" +
                        "                    3\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                }\n" +
                        "            表格格式：\n" +
                        "                Inner：无\n" +
                        "                Outer：无\n" +
                        "                {\n" +
                        "                    解释：覆盖同name的数据段，若不存在则添加到数据序列最后面\n" +
                        "                    key值格式： name:null(不变):null(不变)\n" +
                        "                    value值格式：无\n" +
                        "                    例子： key值=\"name1:null:null\",value值=\"3\"\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    Content-Disposition: form-data; name=\"name1\"\n" +
                        "\n" +
                        "                    xxxx\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    修改成\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    Content-Disposition: form-data; name=\"name1\"\n" +
                        "\n" +
                        "                    3\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                }");
            }
        }else if(cleanButton.isSelected()){
            if(headerButton.isSelected()){
                tipsArea.setText("Header位置： 无");
            }else if(pathButton.isSelected()){
                tipsArea.setText("Path位置：\n" +
                        "    Inner：无\n" +
                        "    Outer：无\n" +
                        "    {\n" +
                        "        解释： 清除整个路径，重新赋值尾 \"/\"+value\n" +
                        "        key值格式：忽略\n" +
                        "        value值格式：无\n" +
                        "        例子：value值=\"d\"\n" +
                        "        /a/b/c/\n" +
                        "        修改成\n" +
                        "        /d\n" +
                        "    }");
            }else if(paramButton.isSelected()){
                tipsArea.setText("Param位置：\n" +
                        "    Inner：无\n" +
                        "    Outer：无\n" +
                        "    {\n" +
                        "        解释： 清除所有参数，赋值为 key+\"=\"+\"value\"\n" +
                        "        key值格式：无\n" +
                        "        value值格式：无\n" +
                        "        例子： key值=\"id3\",value值=\"3\"\n" +
                        "        /a/b/c?id1=1&id2=2\n" +
                        "        修改成\n" +
                        "        /a/b/c?id3=3\n" +
                        "    }");
            }else if(bodyButton.isSelected()){
                tipsArea.setText("Body位置： 支持application/x-www-form-urlencoded、multipart/form-data、application/json、application/xml 和 text/xml\n" +
                        "    application/x-www-form-urlencoded:\n" +
                        "        Inner：无\n" +
                        "        Outer：无\n" +
                        "        {\n" +
                        "            解释：清除所有参数，重新赋值为 key+\"=\"+value\n" +
                        "            key值格式：无\n" +
                        "            value值格式：无\n" +
                        "            例子： key值=\"id3\",value值=\"3\"\n" +
                        "            id1=1&id2=2\n" +
                        "            修改成\n" +
                        "            id3=3\n" +
                        "        }\n" +
                        "    multipart/form-data:\n" +
                        "        文件格式：\n" +
                        "            Inner：无\n" +
                        "            Outer：无\n" +
                        "            {\n" +
                        "                解释：清除所有数据段，重新赋值新字段\n" +
                        "                key值格式： name:filename:Content-Type\n" +
                        "                value值格式：无\n" +
                        "                例子： key值=\"file1:file1.txt:text/plain\",value值=\"3\"\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                Content-Disposition: form-data; name=\"file\"; filename=\"xxx.txt\"\n" +
                        "                Content-Type: text/plain\n" +
                        "\n" +
                        "                xxxxxx\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                修改成\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                Content-Disposition: form-data; name=\"file1\"; filename=\"file1.txt\"\n" +
                        "                Content-Type: text/plain\n" +
                        "\n" +
                        "                3\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "            }\n" +
                        "        表格格式：\n" +
                        "            Inner：无\n" +
                        "            Outer：无\n" +
                        "            {\n" +
                        "                解释：清除所有数据段，重新赋值新字段\n" +
                        "                key值格式： name:null(不变):null(不变)\n" +
                        "                value值格式：无\n" +
                        "                例子： key值=\"name2:null:null\",value值=\"3\"\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                Content-Disposition: form-data; name=\"name1\"\n" +
                        "\n" +
                        "                xxxx\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                修改成\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "                Content-Disposition: form-data; name=\"name2\"\n" +
                        "\n" +
                        "                3\n" +
                        "                -----------------------------195784179425668763703025983801\n" +
                        "            }\n" +
                        "    application/json:\n" +
                        "        Inner：无\n" +
                        "        Outer：无\n" +
                        "        {\n" +
                        "            解释：清除整个JSON数据，赋值为value\n" +
                        "            key值格式： 忽略\n" +
                        "            value值格式：json格式数据\n" +
                        "            例子：无\n" +
                        "        }\n" +
                        "    application/xml 和 text/xml:\n" +
                        "        Inner：无\n" +
                        "        Outer：无\n" +
                        "        {\n" +
                        "            解释：清除整个xml数据，赋值为value\n" +
                        "            key值格式： 忽略\n" +
                        "            value值格式：xml格式数据\n" +
                        "            例子：无\n" +
                        "        }");
            }else{
                tipsArea.setText("Clean功能：  清除所有已有字段，再重新添加新的字段\n" +
                        "    Header位置： 无\n" +
                        "    Path位置：\n" +
                        "        Inner：无\n" +
                        "        Outer：无\n" +
                        "        {\n" +
                        "            解释： 清除整个路径，重新赋值尾 \"/\"+value\n" +
                        "            key值格式：忽略\n" +
                        "            value值格式：无\n" +
                        "            例子：value值=\"d\"\n" +
                        "            /a/b/c/\n" +
                        "            修改成\n" +
                        "            /d\n" +
                        "        }\n" +
                        "    Param位置：\n" +
                        "        Inner：无\n" +
                        "        Outer：无\n" +
                        "        {\n" +
                        "            解释： 清除所有参数，赋值为 key+\"=\"+\"value\"\n" +
                        "            key值格式：无\n" +
                        "            value值格式：无\n" +
                        "            例子： key值=\"id3\",value值=\"3\"\n" +
                        "            /a/b/c?id1=1&id2=2\n" +
                        "            修改成\n" +
                        "            /a/b/c?id3=3\n" +
                        "        }\n" +
                        "    Body位置： 支持application/x-www-form-urlencoded、multipart/form-data、application/json、application/xml 和 text/xml\n" +
                        "        application/x-www-form-urlencoded:\n" +
                        "            Inner：无\n" +
                        "            Outer：无\n" +
                        "            {\n" +
                        "                解释：清除所有参数，重新赋值为 key+\"=\"+value\n" +
                        "                key值格式：无\n" +
                        "                value值格式：无\n" +
                        "                例子： key值=\"id3\",value值=\"3\"\n" +
                        "                id1=1&id2=2\n" +
                        "                修改成\n" +
                        "                id3=3\n" +
                        "            }\n" +
                        "        multipart/form-data:\n" +
                        "            文件格式：\n" +
                        "                Inner：无\n" +
                        "                Outer：无\n" +
                        "                {\n" +
                        "                    解释：清除所有数据段，重新赋值新字段\n" +
                        "                    key值格式： name:filename:Content-Type\n" +
                        "                    value值格式：无\n" +
                        "                    例子： key值=\"file1:file1.txt:text/plain\",value值=\"3\"\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    Content-Disposition: form-data; name=\"file\"; filename=\"xxx.txt\"\n" +
                        "                    Content-Type: text/plain\n" +
                        "\n" +
                        "                    xxxxxx\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    修改成\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    Content-Disposition: form-data; name=\"file1\"; filename=\"file1.txt\"\n" +
                        "                    Content-Type: text/plain\n" +
                        "\n" +
                        "                    3\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                }\n" +
                        "            表格格式：\n" +
                        "                Inner：无\n" +
                        "                Outer：无\n" +
                        "                {\n" +
                        "                    解释：清除所有数据段，重新赋值新字段\n" +
                        "                    key值格式： name:null(不变):null(不变)\n" +
                        "                    value值格式：无\n" +
                        "                    例子： key值=\"name2:null:null\",value值=\"3\"\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    Content-Disposition: form-data; name=\"name1\"\n" +
                        "\n" +
                        "                    xxxx\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    修改成\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                    Content-Disposition: form-data; name=\"name2\"\n" +
                        "\n" +
                        "                    3\n" +
                        "                    -----------------------------195784179425668763703025983801\n" +
                        "                }\n" +
                        "        application/json:\n" +
                        "            Inner：无\n" +
                        "            Outer：无\n" +
                        "            {\n" +
                        "                解释：清除整个JSON数据，赋值为value\n" +
                        "                key值格式： 忽略\n" +
                        "                value值格式：json格式数据\n" +
                        "                例子：无\n" +
                        "            }\n" +
                        "        application/xml 和 text/xml:\n" +
                        "            Inner：无\n" +
                        "            Outer：无\n" +
                        "            {\n" +
                        "                解释：清除整个xml数据，赋值为value\n" +
                        "                key值格式： 忽略\n" +
                        "                value值格式：xml格式数据\n" +
                        "                例子：无\n" +
                        "            }");
            }
        }else{
            tipsShowAll();
        }
    }
    private void tipsShowAll(){
        tipsArea.setText("Add功能：  添加字段，不覆盖已有同名字段\n" +
                "    Header位置：  添加字段到请求头\n" +
                "        Inner内部插：{\n" +
                "            解释：添加到某个字段内，key前加 某个字段+\":\" 即可表示加在哪个字段里面。如果未存在外部字段，重新构造字段加入head。最多支持两层\"key1:key2\"\n" +
                "            key值格式： \"外层字段名:内层字段名\"\n" +
                "            value值格式：无\n" +
                "            例子：key值=\"Cookie:name\",value值=\"456\"，此时\"Cookie:name\"被分割成Cookie和name\n" +
                "            Cookie: name=123 \n" +
                "            修改成\n" +
                "            Cookie: name=123(保留)\n" +
                "            Cookie:name=456\n" +
                "        }\n" +
                "        Outer外部插：{\n" +
                "            解释：直接添加到头的最尾部,距离Body最近的位置\n" +
                "            key值格式： 无\n" +
                "            value值格式：无\n" +
                "            例子：key值=\"Cookie:name\",value值=\"456\",此时\"Cookie:name\"是整个的字段\n" +
                "            Cookie: name=123 \n" +
                "            修改成\n" +
                "            Cookie: name=123(保留)\n" +
                "            Cookie:name:456\n" +
                "        }\n" +
                "    Path位置：添加value值到路径中\n" +
                "        Inner：无\n" +
                "        Outer：无\n" +
                "        {\n" +
                "            解释：在Add功能中，以路径/a/b/c/为例，value注入的位置被划分为0 /a 1 /b 2 /c 3，key值必须为数字，表示插入到路径的哪个地方，\n" +
                "                 同时如果key值小于0则默认加在路径最前面，超过最大位置数的，默认加在路径最后面\n" +
                "            key值格式：必须数字\n" +
                "            value值格式：无\n" +
                "            例子：key值=\"2\",value值=\"d\"\n" +
                "            /a/b/c/\n" +
                "            修改成\n" +
                "            /a/b/d/c\n" +
                "        }\n" +
                "    Param位置：添加字段到Get参数\n" +
                "        Inner头插：{\n" +
                "            解释：直接添加字段到参数的最前面\n" +
                "            key值格式：无\n" +
                "            value值格式：无\n" +
                "            例子： key值=\"id1\",value值=\"3\"\n" +
                "            /a/b/c?id1=1&id2=2\n" +
                "            修改成\n" +
                "            /a/b/c?id1=3&id1=1&id2=2\n" +
                "        }\n" +
                "        Outer尾插：{\n" +
                "            解释：直接添加字段到参数的最后面\n" +
                "            key值格式：无\n" +
                "            value值格式：无\n" +
                "            例子： key值=\"id1\",value值=\"3\"\n" +
                "            /a/b/c?id1=1&id2=2\n" +
                "            修改成\n" +
                "            /a/b/c?id1=1&id2=2&id1=3\n" +
                "        }\n" +
                "    Body位置：支持application/x-www-form-urlencoded、multipart/form-data,application/json、application/xml和text/xml仅被Clean功能支持\n" +
                "        application/x-www-form-urlencoded： url编码，默认是参数结构 a=b&c=d\n" +
                "            Inner头插：{\n" +
                "                解释：类似GET参数插入，直接添加到参数的最前面\n" +
                "                key值格式：无\n" +
                "                value值格式：无\n" +
                "                例子： key值=\"id1\",value值=\"3\"\n" +
                "                id1=1&id2=2\n" +
                "                修改成\n" +
                "                id1=3&id1=1&id2=2\n" +
                "            }\n" +
                "            Outer尾插：{\n" +
                "                解释：类似GET参数插入，直接添加到参数的最后面\n" +
                "                key值格式：无\n" +
                "                value值格式：无\n" +
                "                例子： key值=\"id1\",value值=\"3\"\n" +
                "                id1=1&id2=2\n" +
                "                修改成\n" +
                "                id1=1&id2=2&id1=3\n" +
                "            }\n" +
                "        multipart/form-data： 支持文件格式、表格格式(用户名和密码)\n" +
                "            文件格式：\n" +
                "                Inner头插：{\n" +
                "                    解释：添加到数据序列最前面\n" +
                "                    key值格式： name:filename:Content-Type\n" +
                "                    value值格式：无\n" +
                "                    例子： key值=\"file1:file2:text/plain\",value值=\"3\"\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    Content-Disposition: form-data; name=\"file\"; filename=\"xxx.txt\"\n" +
                "                    Content-Type: text/plain\n" +
                "\n" +
                "                    xxxxxx\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    修改成\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    Content-Disposition: form-data; name=\"file1\"; filename=\"file2\"\n" +
                "                    Content-Type: text/plain\n" +
                "\n" +
                "                    3\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    Content-Disposition: form-data; name=\"file\"; filename=\"xxx.txt\"\n" +
                "                    Content-Type: text/plain\n" +
                "\n" +
                "                    xxxxxx\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                }\n" +
                "                Outer尾插：{\n" +
                "                    解释：添加到数据序列最后面\n" +
                "                    key值格式： name:filename:Content-Type\n" +
                "                    value值格式：无\n" +
                "                    例子： key值=\"file1:file2:text/plain\",value值=\"3\"\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    Content-Disposition: form-data; name=\"file\"; filename=\"xxx.txt\"\n" +
                "                    Content-Type: text/plain\n" +
                "\n" +
                "                    xxxxxx\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    修改成\n" +
                "                \n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    Content-Disposition: form-data; name=\"file\"; filename=\"xxx.txt\"\n" +
                "                    Content-Type: text/plain\n" +
                "\n" +
                "                    xxxxxx\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    Content-Disposition: form-data; name=\"file1\"; filename=\"file2\"\n" +
                "                    Content-Type: text/plain\n" +
                "\n" +
                "                    3\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                }\n" +
                "            表格格式：\n" +
                "                Inner头插：{\n" +
                "                    解释：添加到数据序列最前面\n" +
                "                    key值格式： name:null(不变):null(不变)\n" +
                "                    value值格式：无\n" +
                "                    例子： key值=\"name1:null:null\",value值=\"3\"\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    Content-Disposition: form-data; name=\"name1\"\n" +
                "\n" +
                "                    xxxx\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    修改成\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    Content-Disposition: form-data; name=\"name1\"\n" +
                "\n" +
                "                    3\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    Content-Disposition: form-data; name=\"name1\"\n" +
                "\n" +
                "                    xxxx\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                }\n" +
                "                Outer尾插：{\n" +
                "                    解释：添加到数据序列最后面\n" +
                "                    key值格式： name:null(不变):null(不变)\n" +
                "                    value值格式：无\n" +
                "                    例子： key值=\"file1:null:null\",value值=\"3\"\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    Content-Disposition: form-data; name=\"name1\"\n" +
                "\n" +
                "                    xxxx\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    修改成\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    Content-Disposition: form-data; name=\"name1\"\n" +
                "\n" +
                "                    xxxx\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    Content-Disposition: form-data; name=\"name1\"\n" +
                "\n" +
                "                    3\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                }\n" +
                "Cover功能：  覆盖同名字段\n" +
                "    Header位置：  覆盖请求头同名字段，若字段不存在，则默认添加上去\n" +
                "        Inner内部插：{\n" +
                "            解释：覆盖到某个外部字段内的同名内部字段，若外部字段活内部字段不存在，则添加上去。key前加 某个字段+\":\" 即可表示加在哪个外部字段里面。\n" +
                "                 如果未存在外部字段，重新构造字段加入head。最多支持两层\"key1:key2\"\n" +
                "            key值格式： \"外层字段名:内层字段名\"\n" +
                "            value值格式：无\n" +
                "            例子：key值=\"Cookie:name\",value值=\"456\"，此时\"Cookie:name\"被分割成Cookie和name\n" +
                "            Cookie: name=123 \n" +
                "            修改成\n" +
                "            Cookie: name=456\n" +
                "        }\n" +
                "        Outer外部插：{\n" +
                "            解释：直接添加到头的最尾部,距离Body最近的位置\n" +
                "            key值格式： 无\n" +
                "            value值格式：无\n" +
                "            例子：key值=\"Cookie:name\",value值=\"456\",此时\"Cookie:name\"是整个的字段\n" +
                "            Cookie: name=123 \n" +
                "            修改成\n" +
                "            Cookie: name=123\n" +
                "            Cookie:name:456\n" +
                "        }\n" +
                "    Path位置：   覆盖路径的某个子路径，由key指定\n" +
                "        Inner：无\n" +
                "        Outer：无\n" +
                "        {\n" +
                "            解释：在Cover功能中，以路径/a/b/c/为例，value注入的位置被划分为/a(0) /b(1) /c(2)，key值必须为数字，表示覆盖路径的哪个部分，\n" +
                "                 同时如果key值小于0则默认覆盖路径最前面部分，比如0位置，超过最大位置数的，默认覆盖路径最后面部分，比如2位置\n" +
                "            key值格式：必须数字\n" +
                "            value值格式：无\n" +
                "            例子：key值=\"2\",value值=\"d\"\n" +
                "            /a/b/c/\n" +
                "            修改成\n" +
                "            /a/d/c\n" +
                "        }\n" +
                "    Param位置：   覆盖Get参数同名字段 \n" +
                "        Inner：无\n" +
                "        Outer：无\n" +
                "        {\n" +
                "            解释：直接覆盖同名字段，若不存在则默认加在参数的最后面\n" +
                "            key值格式：无\n" +
                "            value值格式：无\n" +
                "            例子： key值=\"id1\",value值=\"3\"\n" +
                "            /a/b/c?id1=1&id2=2\n" +
                "            修改成\n" +
                "            /a/b/c?id1=3&id2=2\n" +
                "        }\n" +
                "    Body位置：   支持application/x-www-form-urlencoded、multipart/form-data\n" +
                "        application/x-www-form-urlencoded：\n" +
                "            Inner：无\n" +
                "            Outer：无\n" +
                "            {\n" +
                "                解释：类似GET参数覆盖，覆盖同名字段，若不存在，则添加到参数的最后面\n" +
                "                key值格式：无\n" +
                "                value值格式：无\n" +
                "                例子： key值=\"id1\",value值=\"3\"\n" +
                "                id1=1&id2=2\n" +
                "                修改成\n" +
                "                id1=3&id2=2\n" +
                "            }\n" +
                "        multipart/form-data：\n" +
                "            文件格式：\n" +
                "                Inner：无\n" +
                "                Outer：无\n" +
                "                {\n" +
                "                    解释：覆盖同name、同filename、同Content-type的数据段，若无匹配则添加到数据序列最后面\n" +
                "                    key值格式： name:filename:Content-Type\n" +
                "                    value值格式：无\n" +
                "                    例子： key值=\"file:xxx.txt:text/plain\",value值=\"3\"\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    Content-Disposition: form-data; name=\"file\"; filename=\"xxx.txt\"\n" +
                "                    Content-Type: text/plain\n" +
                "\n" +
                "                    xxxxxx\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    修改成\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    Content-Disposition: form-data; name=\"file\"; filename=\"xxx.txt\"\n" +
                "                    Content-Type: text/plain\n" +
                "\n" +
                "                    3\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                }\n" +
                "            表格格式：\n" +
                "                Inner：无\n" +
                "                Outer：无\n" +
                "                {\n" +
                "                    解释：覆盖同name的数据段，若不存在则添加到数据序列最后面\n" +
                "                    key值格式： name:null(不变):null(不变)\n" +
                "                    value值格式：无\n" +
                "                    例子： key值=\"name1:null:null\",value值=\"3\"\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    Content-Disposition: form-data; name=\"name1\"\n" +
                "\n" +
                "                    xxxx\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    修改成\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    Content-Disposition: form-data; name=\"name1\"\n" +
                "\n" +
                "                    3\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                }\n" +
                "Clean功能：  清除所有已有字段，再重新添加新的字段\n" +
                "    Header位置： 无\n" +
                "    Path位置：\n" +
                "        Inner：无\n" +
                "        Outer：无\n" +
                "        {\n" +
                "            解释： 清除整个路径，重新赋值尾 \"/\"+value\n" +
                "            key值格式：忽略\n" +
                "            value值格式：无\n" +
                "            例子：value值=\"d\"\n" +
                "            /a/b/c/\n" +
                "            修改成\n" +
                "            /d\n" +
                "        }\n" +
                "    Param位置：\n" +
                "        Inner：无\n" +
                "        Outer：无\n" +
                "        {\n" +
                "            解释： 清除所有参数，赋值为 key+\"=\"+\"value\"\n" +
                "            key值格式：无\n" +
                "            value值格式：无\n" +
                "            例子： key值=\"id3\",value值=\"3\"\n" +
                "            /a/b/c?id1=1&id2=2\n" +
                "            修改成\n" +
                "            /a/b/c?id3=3\n" +
                "        }\n" +
                "    Body位置： 支持application/x-www-form-urlencoded、multipart/form-data、application/json、application/xml 和 text/xml\n" +
                "        application/x-www-form-urlencoded:\n" +
                "            Inner：无\n" +
                "            Outer：无\n" +
                "            {\n" +
                "                解释：清除所有参数，重新赋值为 key+\"=\"+value\n" +
                "                key值格式：无\n" +
                "                value值格式：无\n" +
                "                例子： key值=\"id3\",value值=\"3\"\n" +
                "                id1=1&id2=2\n" +
                "                修改成\n" +
                "                id3=3\n" +
                "            }\n" +
                "        multipart/form-data:\n" +
                "            文件格式：\n" +
                "                Inner：无\n" +
                "                Outer：无\n" +
                "                {\n" +
                "                    解释：清除所有数据段，重新赋值新字段\n" +
                "                    key值格式： name:filename:Content-Type\n" +
                "                    value值格式：无\n" +
                "                    例子： key值=\"file1:file1.txt:text/plain\",value值=\"3\"\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    Content-Disposition: form-data; name=\"file\"; filename=\"xxx.txt\"\n" +
                "                    Content-Type: text/plain\n" +
                "\n" +
                "                    xxxxxx\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    修改成\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    Content-Disposition: form-data; name=\"file1\"; filename=\"file1.txt\"\n" +
                "                    Content-Type: text/plain\n" +
                "\n" +
                "                    3\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                }\n" +
                "            表格格式：\n" +
                "                Inner：无\n" +
                "                Outer：无\n" +
                "                {\n" +
                "                    解释：清除所有数据段，重新赋值新字段\n" +
                "                    key值格式： name:null(不变):null(不变)\n" +
                "                    value值格式：无\n" +
                "                    例子： key值=\"name2:null:null\",value值=\"3\"\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    Content-Disposition: form-data; name=\"name1\"\n" +
                "\n" +
                "                    xxxx\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    修改成\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                    Content-Disposition: form-data; name=\"name2\"\n" +
                "\n" +
                "                    3\n" +
                "                    -----------------------------195784179425668763703025983801\n" +
                "                }\n" +
                "        application/json:\n" +
                "            Inner：无\n" +
                "            Outer：无\n" +
                "            {\n" +
                "                解释：清除整个JSON数据，赋值为value\n" +
                "                key值格式： 忽略\n" +
                "                value值格式：json格式数据\n" +
                "                例子：无\n" +
                "            }\n" +
                "        application/xml 和 text/xml:\n" +
                "            Inner：无\n" +
                "            Outer：无\n" +
                "            {\n" +
                "                解释：清除整个xml数据，赋值为value\n" +
                "                key值格式： 忽略\n" +
                "                value值格式：xml格式数据\n" +
                "                例子：无\n" +
                "            }");
    }
    private void updateButtonAvailability(){
        if(addButton.isSelected()){
            headerButton.setEnabled(true);
            bodyButton.setEnabled(true);
            pathButton.setEnabled(true);
            paramButton.setEnabled(true);
            innerButton.setEnabled(true);
            outerButton.setEnabled(true);
            if(pathButton.isSelected()){
                innerButton.setEnabled(false);
                outerButton.setEnabled(false);
            }else{
                innerButton.setEnabled(true);
                outerButton.setEnabled(true);
            }
        }else if(coverButton.isSelected()){
            headerButton.setEnabled(true);
            bodyButton.setEnabled(true);
            pathButton.setEnabled(true);
            paramButton.setEnabled(true);
            innerButton.setEnabled(true);
            outerButton.setEnabled(true);
            if(headerButton.isSelected()){
                innerButton.setEnabled(true);
                outerButton.setEnabled(true);
            }else{
                innerButton.setEnabled(false);
                outerButton.setEnabled(false);
            }
        }else if(cleanButton.isSelected()){
            headerButton.setEnabled(false);
            bodyButton.setEnabled(true);
            pathButton.setEnabled(true);
            paramButton.setEnabled(true);
            innerButton.setEnabled(false);
            outerButton.setEnabled(false);
        }else{
            headerButton.setEnabled(true);
            bodyButton.setEnabled(true);
            pathButton.setEnabled(true);
            paramButton.setEnabled(true);
            innerButton.setEnabled(true);
            outerButton.setEnabled(true);
        }
    }

    public String getTabCaption() {
        return "Web API Security Detection System";//插件名称
    }

    public Component getUiComponent() {
        return root;
    }


    /* ========================================================================================
     *  自定义 requestResponseClass总类、request、header、body类及相关操作方法
     *  ========================================================================================
     * */
    class RequestResponseClass {
        MyRequest beforeRequest;
        MyRequest afterRequest;
        IHttpService service;
        boolean update;

        int hash;
        String method;
        String host;
        String port;
        String status;
        String length;
        String mime;
        String cookies;
        String url;

        String result;

        public RequestResponseClass(IRequestInfo beforeIRequestInfo, byte[] beforeRequest){
            this.beforeRequest = new MyRequest(beforeIRequestInfo,beforeRequest);
            update = false;
            byte[] after = beforeRequest.clone();
            this.afterRequest = new MyRequest(helpers.analyzeRequest(after),after);
            hash = beforeIRequestInfo.hashCode();
            method = beforeIRequestInfo.getMethod();
            //Mime类型
            if(beforeIRequestInfo.getContentType()==IRequestInfo.CONTENT_TYPE_URL_ENCODED){
                mime = "Urlencode";
            }else if(beforeIRequestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_MULTIPART){
                mime = "Multipart";
            }else if(beforeIRequestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_XML){
                mime = "Xml";
            }else if(beforeIRequestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_JSON){
                mime = "Json";
            }else if(beforeIRequestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_AMF){
                mime = "Amf";
            }else if(beforeIRequestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_NONE) {
                mime = "None";
            } else{
                mime = "Unknown";
            }
            //
            List<String>headers =  beforeIRequestInfo.getHeaders();
            port = "80";
            status = host = cookies = url = result = "";
            length = "0";
            String uri = "";
            for(String header : headers){
                if(header.indexOf(":")>=0) {
                    if (header.substring(0, header.indexOf(":")).trim().equals("Host")) { //获取port、host
                        uri = header.replaceFirst("Host\\s*:\\s*", "").trim();
                        try{
                            port = header.substring(header.lastIndexOf(":") + 1);
                            Integer.valueOf(port);
                        }catch (Exception e){
                            port = "80";
                        }
                        try{
                            host = uri.substring(0,uri.lastIndexOf(":")).trim();
                        }catch (Exception e){
                            host = uri;
                        }
                        continue;
                    }
                    if (header.substring(0, header.indexOf(":")).trim().equals("Cookie")) {//获取Cookie
                        cookies = header.replaceFirst("Cookie\\s*:\\s*", "");
                        continue;
                    }
                    if (header.substring(0, header.indexOf(":")).trim().equals("Content-Length")) {//获取length
                        length = header.replaceFirst("Content-Length\\s*:\\s*", "");
                        continue;
                    }
                }
            }
            String methodURLProtocol= null;
            if(!headers.isEmpty()) methodURLProtocol = headers.get(0);
            url = uri+methodURLProtocol.split("\\s+")[1];
            service = helpers.buildHttpService(host,Integer.valueOf(port),false);
        }

        public int getHashcode(){ return hash; }
        public String getMethod(){ return method; }
        public String getHost(){ return host; }
        public String getPort(){ return port; }
        public String getStatus(){ return status; }
        public String getLength(){ return length; }
        public String getMime(){ return mime; }
        public String getCookies(){ return cookies; }
        public String getUrl(){ return url; }
        public String getResult(){ return result; }
        public String getBeforeRequestText(){return beforeRequest.getRequestText();}
        public String getAfterRequestText(){return afterRequest.getRequestText();}
        public MyRequest getAfterRequest(){return afterRequest;}
        public IHttpService getService(){return service;}
        public boolean getUpdate(){return update;}
        public void resetAfterRequest(){
            byte[] after = this.beforeRequest.getRequest().clone();
            this.afterRequest = new MyRequest(helpers.analyzeRequest(after),after);
        }

        public void setUpdateFalse(){update = false;}
        public void setUpdateTrue(){update = true;}
        public void setResult(String result){this.result = result;}

    }

    class MyRequest {
        IRequestInfo requestInfo;
        byte[] request;
        IHttpRequestResponse response;
        String requestText;
        MyHeader header;
        MyBody body;
        long responseTime;//请求时间

        MyRequest(IRequestInfo requestInfo, byte[] request){
            this.request = request;
            this.requestInfo = requestInfo;
            this.requestText = helpers.bytesToString(request);
            this.response = null;
            header = new MyHeader(requestInfo.getHeaders());

            int bodyOffset = requestInfo.getBodyOffset();
            String requestString = new String(this.request); //byte[] to String
            String bodyString = requestString.substring(bodyOffset);
            byte[] byte_body = bodyString.getBytes();  //String to byte[]
            this.body = new MyBody(byte_body,this.requestInfo.getContentType(),this.requestInfo.getHeaders());
        }

        public void reBuildRequest(){  //根据header对象和body对象来重新构造新的request请求包||一般在修改header或body后使用
            this.request = helpers.buildHttpMessage(this.header.getHeaders(), this.body.getBody());
            this.requestInfo = helpers.analyzeRequest(this.request);
            this.requestText = helpers.bytesToString(this.request);
        }

        public void modifyrequest(int method,int position,int inOrOut,String key,String value){
            if(method!=-1&&position!=-1) {//TODO 去掉&inorOut！=-1是否会出现问题
                if (position == UpdateData.PAYLOAD_HEADER || position == UpdateData.PAYLOAD_PARAM || position == UpdateData.PAYLOAD_PATH) {
                    this.header.setHeaders(method, position, inOrOut, key, value);
                } else if (position == UpdateData.PAYLOAD_BODY) {
                    this.body.setBody(method, position, inOrOut, key, value);
                }
            }
        }

        public String getRequestText(){
            return requestText;
        }
        public byte[] getRequest(){
            return request;
        }
        public long getResponseTime() { return responseTime; }
        public void setResponseTime(long responseTime) { this.responseTime = responseTime; }
        public void setResponse(IHttpRequestResponse response){this.response = response;}
        public IHttpRequestResponse getResponse(){return response;}
    }

    class MyHeader{
        List<String> headers;
        MyHeader(List<String> headers){
            this.headers = headers;
        }

        List<String> getHeaders(){return headers;}

        void setHeaders(int method,int position,int inOrOut,String keys,String value) {
            //header头部第一行数据拆分
            String[] divide1 = headers.get(0).split("\\s+"); //分隔开请求方法+资源请求路径+协议
            String message_Method = divide1[0];
            String message_PathParam = divide1[1];
            String message_Protocol = divide1[2];
            String[] divide2 = message_PathParam.split("\\?");
            String message_Paths = divide2[0];
            String message_Param = "";
            if(divide2.length>1) {
                message_Param = helpers.urlDecode(divide2[1]);
            }

            if(method == UpdateData.PAYLOAD_ADD){
                if(position == UpdateData.PAYLOAD_HEADER){
                    if(inOrOut == UpdateData.PAYLOAD_OUTER){
                        headers.add(keys+": "+value);
                    }else if(inOrOut == UpdateData.PAYLOAD_INNER){
                        String key[] = keys.split("\\s*:\\s*");
                        if(key.length!=2){System.out.println("key值不符合要求，只能且必须有一个：");return;} //长度少于两个，不符合要求
                        boolean flag = false;
                        if(key.length>2) {
                            System.out.println("header头部加入不能超过两层");
                        }
                        for(int i =0; i<headers.size();i++){
                            if(headers.get(i).indexOf(":")>=0) {
                                if (headers.get(i).substring(0, headers.get(i).indexOf(":")).trim().equals(key[0].trim())) {
                                    if ((headers.get(i).lastIndexOf(";") + 1) == headers.get(i).length()) {
                                        headers.set(i, headers.get(i).concat(key[1] + " = " + value));
                                    } else {
                                        headers.set(i, headers.get(i).concat(";" + key[1] + " = " + value));
                                    }
                                    flag = true;
                                }
                            }
                        }
                        if(!flag){ //表示未找到key[0]对应的头字段，未添加上，自行加上
                            headers.add(key[0]+": "+key[1]+" = "+value);
                        }
                    }
                }else if(position == UpdateData.PAYLOAD_PARAM){
                    if(divide2.length>1) {
                        message_Param = divide2[1];
                    }
                    if(inOrOut == UpdateData.PAYLOAD_OUTER){
                        message_Param = (message_Param+"&"+keys+"="+helpers.urlEncode(value));
                    }else if(inOrOut == UpdateData.PAYLOAD_INNER){
                        message_Param = (keys+"="+helpers.urlEncode(value)+"&"+message_Param);
                    }
                    headers.set(0, message_Method + " " + message_Paths + "?" + message_Param + " " + message_Protocol);
                }else if(position == UpdateData.PAYLOAD_PATH){
                    String[] path = message_Paths.split("\\s*/+\\s*");
                    int keykey;
                    try{
                        keykey = Integer.parseInt(keys);
                    }catch (Exception e){
                        return;
                    }
                    message_Paths = "";
                    int p = 0;
                    if(keykey<(path.length)){
                        while(keykey>0){
                            if(path[p].equals("")) p++;
                            else{
                                message_Paths+=("/"+path[p++]);
                                keykey--;
                            }

                        }
                        message_Paths+=("/"+value);
                        for(;p<path.length;p++) {
                            if(path[p].equals("")) continue; //无效添加
                            message_Paths+=("/"+path[p]);
                        }
                    }
                    else if(keykey>=(path.length)){
                        for(;p<path.length;p++) {
                            if(path[p].equals("")) continue; //无效添加
                            message_Paths+=("/"+path[p]);
                        }
                        message_Paths+=("/"+value);
                    }
                    try {
                        headers.set(0, message_Method + " " + message_Paths + "?" + new URI(null, null, message_Param, null).toASCIIString() + " " + message_Protocol);
                    } catch (URISyntaxException e) {
                        e.printStackTrace();
                    }
                }
            }else if(method == UpdateData.PAYLOAD_COVER){
                if(position == UpdateData.PAYLOAD_HEADER){
                    boolean outflag = false; //外部字段是否已存在
                    boolean inflag = false;//内部字段是否已存在
                    if(inOrOut == UpdateData.PAYLOAD_OUTER){
                        for(int i =0; i<headers.size();i++){
                            if(headers.get(i).indexOf(":")>=0) {
                                if (headers.get(i).substring(0, headers.get(i).indexOf(":")).trim().equals(keys.trim())) {
                                    headers.set(i, keys + ": " + value);
                                    outflag = true;
                                    break;
                                }
                            }
                        }
                        if(!outflag){
                            headers.add(keys+": "+value);
                        }
                    }else if(inOrOut == UpdateData.PAYLOAD_INNER){
                        String key[] = keys.trim().split("\\s*:\\s*");
                        if(key.length!=2) {
                            System.out.println("key字段只支持两层结构 key0:key1");
                            return;
                        }
                        for(int i =0; i<headers.size();i++){
                            if(headers.get(i).indexOf(":")>=0) {
                                if (headers.get(i).substring(0, headers.get(i).indexOf(":")).trim().equals(key[0].trim())) {
                                    outflag = true;
                                    String left = headers.get(i).split("\\s*:\\s*")[0].trim();
                                    String[] rights = headers.get(i).split("\\s*:\\s*")[1].trim().split("\\s*;\\s*");
                                    String right = "";
                                    for (int j = 0; j < rights.length; j++) {
                                        if(rights[j].trim().indexOf("=")>=0) {
                                            if (rights[j].trim().substring(0, rights[j].trim().indexOf("=")).trim().equals(key[1].trim())) {
                                                inflag = true;
                                                rights[j] = key[1] + "=" + value;
                                            }
                                        }
                                    }
                                    for (int j = 0; j < rights.length; j++) {
                                        right += (rights[j] + ";");
                                    }
                                    if (!inflag) {//内部字段不存在
                                        right += (key[1] + " = " + value);
                                    }
                                    headers.set(i, left + ": " + right);
                                }
                            }
                        }
                        if(!outflag){ //外部字段不存在
                            headers.add(key[0]+": "+key[1]+" = "+value);
                        }
                    }
                }else if(position == UpdateData.PAYLOAD_PARAM){
                    boolean flag = false;
                    if(divide2.length>1) {
                        message_Param = divide2[1];
                    }
                    String[]  message_Params =  message_Param.trim().split("\\s*&\\s*");
                    for(int i=0;i<message_Params.length;i++){
                        if(message_Params[i].trim().indexOf("=")>=0) {
                            if (message_Params[i].trim().substring(0, message_Params[i].trim().indexOf("=")).trim().equals(keys.trim())) { //省略用户输入的key的前后空格
                                message_Params[i] = (keys + "=" + helpers.urlEncode(value));
                                flag = true;
                            }
                        }
                    }
                    message_Param="";
                    if(!flag){//未找到指定key参数，自行加上
                        if(message_Params.length!=0) message_Param+=(keys+"="+helpers.urlEncode(value)+"&");
                        else message_Param+=(keys+"="+helpers.urlEncode(value));
                    }
                    for(int i=0;i<message_Params.length;i++){
                        if(i == (message_Params.length-1)){
                            message_Param+=message_Params[i];
                        }else{
                            message_Param+=(message_Params[i]+"&");
                        }
                    }
                    headers.set(0, message_Method + " " + message_Paths + "?" + message_Param + " " + message_Protocol);

                }else if(position == UpdateData.PAYLOAD_PATH){
                    String[] path = message_Paths.split("\\s*/+\\s*");
                    boolean islast = false;
                    if((message_Paths.lastIndexOf("'/")+1) == message_Paths.length()) islast = true;
                    int keykey;
                    try{
                        keykey = Integer.parseInt(keys);
                    }catch (Exception e){
                        return;
                    }
                    message_Paths = "";
                    int p = 1;
                    if(keykey>=0&&keykey<path.length-2){
                        path[keykey+1] = value;
                    }else if(keykey>=path.length-2){
                        path[path.length-1] = value;
                    }else if(keykey<0){
                        path[1] = value;
                    }
                    for(String pathpath : path){
                        if(!pathpath.equals("")) message_Paths+=("/"+pathpath);
                    }
                    if(islast) message_Paths+="/";
                    try {
                        headers.set(0, message_Method + " " + message_Paths + "?" + new URI(null, null, message_Param, null).toASCIIString() + " " + message_Protocol);
                    } catch (URISyntaxException e) {
                        e.printStackTrace();
                    }
                }
            }else if(method == UpdateData.PAYLOAD_CLEAN){
                if(position == UpdateData.PAYLOAD_PARAM){
                    message_Param = (keys+"="+helpers.urlEncode(value));
                    headers.set(0, message_Method + " " + message_Paths + "?" + message_Param + " " + message_Protocol);

                }else if(position == UpdateData.PAYLOAD_PATH){
                    message_Paths = ("/"+value);
                    try {
                        headers.set(0, message_Method + " " + message_Paths + "?" + new URI(null, null, message_Param, null).toASCIIString() + " " + message_Protocol);
                    } catch (URISyntaxException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }

    class MyBody{
        byte[] body;
        int Mime_type;
        String boundary;
        String Content_type;

        MyBody(byte[] body,int Mime_type,List<String> headers){
            this.body = body;
            this.Content_type = Content_type;
            for(String header:headers){
                if(header.indexOf(":")>=0) {
                    if (header.substring(0, header.indexOf(":")).trim().equals("Content-Type")) {
                        this.Content_type = header.substring(header.indexOf(":") + 1).trim();

                    }
                }
            }
            this.Mime_type = Mime_type;

        }

        byte[] getBody(){return this.body;}

        void setBody(int method,int position,int inOrOut,String keys,String value){
            String bodyString = helpers.bytesToString(this.body);
            if(Mime_type==IRequestInfo.CONTENT_TYPE_URL_ENCODED||Mime_type == IRequestInfo.CONTENT_TYPE_UNKNOWN||Mime_type == IRequestInfo.CONTENT_TYPE_NONE){
                if(method == UpdateData.PAYLOAD_ADD){
                    if(inOrOut == UpdateData.PAYLOAD_INNER){
                        bodyString = keys+"="+helpers.urlEncode(value)+"&"+bodyString;
                    }else if(inOrOut == UpdateData.PAYLOAD_OUTER){
                        bodyString = bodyString+("&"+keys+"="+helpers.urlEncode(value));
                    }
                    try {
                        this.body = helpers.stringToBytes(new URI(null, null, bodyString, null).toASCIIString());
                    }catch (URISyntaxException e) {
                        e.printStackTrace();
                    }
                }else if(method == UpdateData.PAYLOAD_COVER){
                    String[] params = bodyString.split("\\s*&\\s*");
                    bodyString = "";
                    boolean flag = false; //flag 为true则表示覆盖成功，为false表示覆盖不成功，即不存在该字段，默认加上
                    for(String param:params){
                        if (param.indexOf("=")>=0&&param.substring(0, param.indexOf("=")).trim().equals(keys.trim())) {//存疑：如果参数是不带=的情况该怎么处理！！！！！！！！！！！
                            bodyString += (keys + "=" + helpers.urlEncode(value) + "&");
                            flag = true;
                        }else {
                            bodyString += (param + "&");
                        }
                    }
                    if(flag == false){
                        bodyString+=(keys+"="+helpers.urlEncode(value)+"&");
                    }
                    if(bodyString.lastIndexOf("&")==(bodyString.length()-1)){
                        bodyString=bodyString.substring(0,bodyString.lastIndexOf("&"));
                    }
                    //this.body = helpers.stringToBytes(helpers.urlEncode(bodyString));
                    this.body = helpers.stringToBytes(bodyString);
                }else if(method == UpdateData.PAYLOAD_CLEAN){
                    //this.body =helpers.stringToBytes(helpers.urlEncode(keys+"="+value));
                    if(keys!=null&&keys!=""){
                        this.body = helpers.stringToBytes( value);
                    }else {
                        this.body = helpers.stringToBytes(keys + "=" + value);
                    }
                }
            }else if(Mime_type == IRequestInfo.CONTENT_TYPE_MULTIPART){
                //截取boundary分界值
                String []content_types = this.Content_type.split("\\s*;\\s*");
                for(String type:content_types){
                    if(type.indexOf("=")>=0) { //不带=号，默认格式不对
                        if (type.substring(0, type.indexOf("=")).trim().equals("boundary")) {
                            this.boundary = type.split("\\s*=\\s*")[1];
                        }
                    }else{
                        System.out.println("boundary的格式不对，不带等号");
                    }
                }
                //以boundary分界值分割整个body
                String []key = keys.split(":"); //分割keys值，获取name:filename:Content-Type值
                String []boundary_structure = bodyString.split("[\r,\n,\r\n]*"+ "--" +this.boundary+"[\r,\n,\r\n]*");
                String bodyString_tmp="";
                if(key.length!=3){
                    System.out.println("Key值格式不对，应为：name:filename:Content-Type");
                    return;
                }
                //执行具体修改方式
                if(method == UpdateData.PAYLOAD_ADD){ //添加数据，无论是否重复
                    if(inOrOut == UpdateData.PAYLOAD_INNER){//添加到body最上面
                        bodyString_tmp += ("--"+this.boundary + "\r\n" + "Content-Disposition: form-data; name=\"" + key[0] + "\"");
                        if (!key[1].equals("null")) {
                            bodyString_tmp += ("; filename=\"" + key[1] + "\"");
                        }
                        bodyString_tmp += "\r\n";
                        if (!key[2].equals("null")) {
                            bodyString_tmp += ("Content-Type: " + key[2] + "\r\n");
                        }
                        bodyString_tmp += ("\r\n"+value + "\r\n");
                        bodyString = bodyString_tmp+bodyString;
                    }else if(inOrOut == UpdateData.PAYLOAD_OUTER){ //添加到body最下面
                        for(String structure:boundary_structure){//先添加上原先的数据
                            if(!structure.trim().equals("")&&!structure.trim().equals("--")){
                                bodyString_tmp += ("--" + this.boundary + "\r\n" + structure + "\r\n");
                            }
                        }
                        //再添加新增数据
                        bodyString_tmp += ("--" + this.boundary + "\r\n" + "Content-Disposition: form-data; name=\"" + key[0] + "\"");
                        if (!key[1].equals("null")) {
                            bodyString_tmp += ("; filename=\"" + key[1] + "\"");
                        }
                        bodyString_tmp += "\r\n";
                        if (!key[2].equals("null")) {
                            bodyString_tmp += ("Content-Type: " + key[2] + "\r\n");
                        }
                        bodyString_tmp += ("\r\n"+value + "\r\n");
                        bodyString_tmp += ("--" + boundary+"--\r\n");
                        bodyString = bodyString_tmp;
                    }
                }else if(method == UpdateData.PAYLOAD_COVER){ //覆盖模式下，inOrOut无效
                    boolean flag = false;
                    for(String structure:boundary_structure){
                        if(!structure.trim().equals("")){
                            String [] layers = structure.trim().split("[\r,\n,\r\n]+");
                            for(String layer:layers){
                                //System.out.println(layer);
                                if(layer.trim().startsWith("Content-Disposition")){
                                    String name = "";
                                    String filename = "";
                                    for(String keyvalue:layer.split("\\s*"+";"+"\\s*")){
                                        if(keyvalue.trim().startsWith("name")) {
                                            name = keyvalue.trim();
                                        }else if(keyvalue.trim().startsWith("filename")) {
                                            filename = keyvalue.trim();
                                        }
                                    }
                                    if(name.split("=+").length>=2&&name.split("=+")[1].equals("\"" + key[0] + "\"")&&((filename.equals("")&&key[1].equals("null"))||(filename.split("=+").length>=2&&filename.split("=+")[1].equals("\"" + key[1] + "\"")))){
                                        bodyString_tmp += ("--" + this.boundary + "\r\n" + "Content-Disposition: form-data; name=\"" + key[0] + "\"");
                                        if (!key[1].equals("null")) {
                                            bodyString_tmp += ("; filename=\"" + key[1] + "\"");
                                        }
                                        bodyString_tmp += "\r\n";
                                        if (!key[2].equals("null")) {
                                            bodyString_tmp += ("Content-Type: " + key[2] + "\r\n");
                                        }
                                        bodyString_tmp += ("\r\n"+value + "\r\n");
                                        flag = true;
                                        break;
                                    }else {
                                        bodyString_tmp += ("--" + this.boundary + "\r\n" + structure + "\r\n");
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if(!flag){
//                        if(inOrOut == UpdateData.PAYLOAD_OUTER) { //区分头加还是尾加
//                            bodyString_tmp += ("--" + this.boundary + "\r\n" + "Content-Disposition: form-data; name=\"" + key[0] + "\"");
//                            if (!key[1].equals("null")) {
//                                bodyString_tmp += ("; filename=\"" + key[1] + "\"");
//                            }
//                            bodyString_tmp += "\r\n";
//                            if (!key[2].equals("null")) {
//                                bodyString_tmp += ("Content-Type: " + key[2] + "\r\n");
//                            }
//                            bodyString_tmp += ("\r\n"+value + "\r\n");
//                        }else if(inOrOut == UpdateData.PAYLOAD_INNER){
//                            String tmp = "";
//                            tmp += ("--" + this.boundary + "\r\n" + "Content-Disposition: form-data; name=\"" + key[0] + "\"");
//                            if (!key[1].equals("null")) {
//                                tmp += ("; filename=\"" + key[1] + "\"");
//                            }
//                            tmp += "\r\n";
//                            if (!key[2].equals("null")) {
//                                tmp += ("Content-Type: " + key[2] + "\r\n");
//                            }
//                            tmp += ("\r\n"+value + "\r\n");
//                            bodyString_tmp = tmp + bodyString_tmp;
//                        }
                        bodyString_tmp += ("--" + this.boundary + "\r\n" + "Content-Disposition: form-data; name=\"" + key[0] + "\"");
                        if (!key[1].equals("null")) {
                            bodyString_tmp += ("; filename=\"" + key[1] + "\"");
                        }
                        bodyString_tmp += "\r\n";
                        if (!key[2].equals("null")) {
                            bodyString_tmp += ("Content-Type: " + key[2] + "\r\n");
                        }
                        bodyString_tmp += ("\r\n"+value + "\r\n");
                    }
                    bodyString_tmp += ("--" + boundary+"--\r\n");
                    bodyString = bodyString_tmp;
                }else if(method == UpdateData.PAYLOAD_CLEAN){ //清除整个body，构造新的数据
                    bodyString_tmp += ("--" + this.boundary + "\r\n" + "Content-Disposition: form-data; name=\"" + key[0] + "\"");
                    if (!key[1].equals("null")) {
                        bodyString_tmp += ("; filename=\"" + key[1] + "\"");
                    }
                    bodyString_tmp += "\r\n";
                    if (!key[2].equals("null")) {
                        bodyString_tmp += ("Content-Type: " + key[2] + "\r\n");
                    }
                    bodyString_tmp += ("\r\n"+value + "\r\n");
                    bodyString_tmp += ("--" + boundary+"--\r\n");
                    bodyString = bodyString_tmp;
                }
                this.body = helpers.stringToBytes(bodyString);
            }else if(Mime_type == IRequestInfo.CONTENT_TYPE_XML){
                if(method == UpdateData.PAYLOAD_CLEAN){
                    this.body = helpers.stringToBytes(value);
                }
            }else if(Mime_type == IRequestInfo.CONTENT_TYPE_JSON){
                if(method == UpdateData.PAYLOAD_CLEAN){
                    this.body = helpers.stringToBytes(value);
                }
            }else if(Mime_type == IRequestInfo.CONTENT_TYPE_AMF){

            }else{

            }
        }
    }

}
