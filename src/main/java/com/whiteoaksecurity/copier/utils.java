package com.whiteoaksecurity.copier;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static com.whiteoaksecurity.copier.CopyProfile.NONE_CONTENT;

public class utils {

    public static ArrayList<Rule> listAddList(ArrayList<Rule> requestLocateRules, ArrayList<Rule> responseLocateRules) {
        ArrayList<Rule> locateRules = new ArrayList<>();
        locateRules.addAll(requestLocateRules);
        locateRules.addAll(responseLocateRules);
        return locateRules;
    }

    //从所有规则中找到 开启非提取功能的规则
    public static ArrayList<Rule> getEnabledReplaceRules(ArrayList<Rule> rules) {
        ArrayList<Rule> replaceRules = new ArrayList<>();
        for(Rule rule : rules){
            if (rule.isEnabledRule() && !rule.isLocateRule()){
                replaceRules.add(rule);
            }
        }
        return replaceRules;
    }

    //从所有规则中找到 开启了提取功能的规则
    public static ArrayList<Rule> getEnabledLocateRules(ArrayList<Rule> rules) {
        ArrayList<Rule> locateRules = new ArrayList<>();
        for(Rule rule : rules){
            if (rule.isEnabledRule() && rule.isLocateRule()){
                locateRules.add(rule);
            }
        }
        return locateRules;
    }

    //	检查是否使用Json格式导出
    public static boolean checkUseJsonFormat(ArrayList<Rule> locateRules) {
        for (Rule rule : locateRules) {
            if (rule.isJsonFormat())
                return true;
        }
        return false;
    }

    //从所有提取规则中获取最后一条规则
    public static Rule getLastLocateRule(ArrayList<Rule> locateRules) {
        Rule locateRule = null;
        if (locateRules.size() > 0){
            locateRule = locateRules.get(locateRules.size() - 1);
            if (locateRules.size() > 1){
                System.out.println(locateRule.toString());
            }
        }
        return locateRule;
    }

    /**
     * 根据当前的规则值和字符串内容 判断是否需要进行base64编码
     * @param string 需要编码的字符串
     * @param enabledBase64 是否需要编码
     * @return
     */
    public static String base64EncodeStrWithCheck(String string,  boolean enabledBase64) {
        if (!string.isEmpty() && !NONE_CONTENT.equals(string) && enabledBase64){
            string = base64EncodeStr(string);
        }
        return string;
    }

    /**
     * 进行base64编码字符串
     * @return
     */
    public static String base64EncodeStr(String string) {
        // 将字符串转换为字节数组
        byte[] bytes = string.getBytes(StandardCharsets.UTF_8);
        // 使用 Base64 进行编码
        String encodedString = Base64.getEncoder().encodeToString(bytes);
        return encodedString;
    }

    /**
     * 获取响应头
     */
     public static String getResponseHeaders(HttpResponse httpResponse) {
        String entireResponse = httpResponse.toByteArray().toString();

        String responseHeaders = "";
        if (httpResponse.bodyOffset()>0){
            responseHeaders = entireResponse.substring(0, httpResponse.bodyOffset()).trim();
        } else if (entireResponse.contains(CopyProfile.SPILT)){
            System.out.println(String.format("获取响应头发生错误: bodyOffset=[%s] 尝试切割方案获取请求头", httpResponse.bodyOffset()));
            responseHeaders = entireResponse.split(CopyProfile.SPILT,2)[0];
        } else {
            System.out.println("获取响应头发生错误: 当前不包含(换行*2)特征 返回空值");
        }
        return responseHeaders;
    }

    public static String getRequestHeaders(HttpRequest httpRequest) {
        String requestHeaders = "";

        String entireRequest = httpRequest.toByteArray().toString();

        if (httpRequest.bodyOffset() > 0){
            requestHeaders = entireRequest.substring(0, httpRequest.bodyOffset()).trim();
        } else if (entireRequest.contains(CopyProfile.SPILT)){
            System.out.println(String.format("获取请求头发生错误: bodyOffset=[%s] 尝试切割方案获取请求头", httpRequest.bodyOffset()));
            requestHeaders = entireRequest.split(CopyProfile.SPILT,2)[0];
        } else {
            System.out.println("获取请求头发生错误: 当前不包含(换行*2)特征 返回全文作为请求头");
        }
        return requestHeaders;
    }

    /*
        修改替换规则为提取规则,提取对象为所有位置
     */
    public static ArrayList<Rule> fixReplaceRulesToLocateRules(ArrayList<Rule> replaceRules) {
        for (Rule rule: replaceRules){
            rule.setLocation(0); //Case 0 保存全文
        }
        return replaceRules;
    }

    /**
     * 追加写入到文件中
     */
    public static void writeToFileAppend(Path path, String content, Charset charset) throws IOException {
        //StandardOpenOption.CREATE 在文件不存在时创建文件
        //StandardOpenOption.APPEND 追加写入
        Files.write(path, content.getBytes(charset), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    /**
     * 覆盖写入到文件中
     */
    public static void writeToFileCover(Path path, String content, Charset charset) throws IOException {
        //StandardOpenOption.TRUNCATE_EXISTING 覆盖写入
        Files.write(path, content.getBytes(charset), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }

    /**
     * 保存到单个文件
     * @param copyBuffer
     */
    public static void saveToFile(String copyBuffer) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("选择文件保存路径:");
        int userSelection = fileChooser.showSaveDialog(null);
        //JFileChooser.APPROVE_OPTION: 用户点击了“确定”或“打开”按钮。
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileToSave = fileChooser.getSelectedFile();
            try {
                writeToFileAppend(fileToSave.toPath(), copyBuffer, StandardCharsets.UTF_8);
                JOptionPane.showMessageDialog(null, "文件保存成功: " + fileToSave.toPath());
            } catch (IOException e) {
                JOptionPane.showMessageDialog(null, "文件保存失败：" + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        } else {
            JOptionPane.showMessageDialog(null, "用户取消保存!");
        }
    }

    /**
     * 保存到多个文件
     * @param copyBuffer
     */
    public static void saveToMultipleFiles(String copyBuffer) {
        // 创建一个文件夹选择框
        JFileChooser folderChooser = new JFileChooser();
        folderChooser.setDialogTitle("选择文件夹保存路径:");
        folderChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY); // 只选择文件夹
        int userSelection = folderChooser.showSaveDialog(null);
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File folderToSave = folderChooser.getSelectedFile();

            try {
                // 使用正则表达式分割字符串
                java.util.List<String> parts = List.of(copyBuffer.split(CopyProfile.CONCAT));

                // 检查文件夹是否存在，不存在则创建
                if (!folderToSave.exists()) {
                    folderToSave.mkdirs();
                }

                // 保存内容到文件夹中的多个文件
                for (int i = 0; i < parts.size(); i++) {
                    String fileName = (i + 1) + ".txt"; // 文件名
                    Path filePath = folderToSave.toPath().resolve(fileName);
                    String content = parts.get(i);
                    writeToFileCover(filePath, content, StandardCharsets.UTF_8);
                }
                JOptionPane.showMessageDialog(null, "文件批量保存成功: " + folderToSave.toPath());
            } catch (IOException e) {
                JOptionPane.showMessageDialog(null, "文件批量保存出错: " + e.getMessage());
            }
        } else {
            JOptionPane.showMessageDialog(null, "用户取消保存!");
        }
    }

    /**
     * 保存到剪贴板
     * @param copyBuffer
     */
    public static void saveToClipboard(String copyBuffer) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(copyBuffer), null);
        JOptionPane.showMessageDialog(null, "写入粘贴板成功!");
    }

    /**
     *
     * @param copyBuffer
     */
    public static void WriteResultToFileOrClipboard(String copyBuffer) {
        // 弹出对话框让用户选择操作类型
        int option = JOptionPane.showOptionDialog(
                null,
                "请选择您想要的操作：",
                "文件保存选项",
                JOptionPane.DEFAULT_OPTION,
                JOptionPane.PLAIN_MESSAGE,
                null,
                new Object[]{"保存到单个文件", "保存到多个文件", "保存到剪贴板"},
                "保存到单个文件"
        );

        switch (option) {
            case 0: // 单个文件
                saveToFile(copyBuffer);
                break;
            case 1: // 多个文件
                saveToMultipleFiles(copyBuffer);
                break;
            case 2: // 保存到剪贴板
                saveToClipboard(copyBuffer);
                break;
            default: // 剪贴板
                JOptionPane.showMessageDialog(null, "用户取消保存!");
        }
    }


    /**
     * 获取body的字符串 不乱码的那种
     */
    public static String getBodyStr(ByteArray bodyBytes, Charset charset) {
        return new String(bodyBytes.getBytes(), charset);
    }
}
