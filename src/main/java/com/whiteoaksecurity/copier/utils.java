package com.whiteoaksecurity.copier;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;

public class utils {

    public static ArrayList<Rule> listAddList(ArrayList<Rule> requestLocateRules, ArrayList<Rule> responseLocateRules) {
        ArrayList<Rule> locateRules = new ArrayList<>();
        locateRules.addAll(requestLocateRules);
        locateRules.addAll(responseLocateRules);
        return locateRules;
    }

    //从所有规则中找到 开启非提取功能的规则
    public static ArrayList<Rule> getReplaceRules(ArrayList<Rule> rules) {
        ArrayList<Rule> replaceRules = new ArrayList<>();
        for(Rule rule : rules){
            if (!rule.isStoreLocate()){
                replaceRules.add(rule);
            }
        }
        return replaceRules;
    }

    //从所有规则中找到 开启了提取功能的规则
    public static ArrayList<Rule> getLocateRules(ArrayList<Rule> rules) {
        ArrayList<Rule> locateRules = new ArrayList<>();
        for(Rule rule : rules){
            if (rule.isStoreLocate()){
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
    public static Rule getLocateRule(ArrayList<Rule> locateRules) {
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
     * @param noneContent 代表空值的常量
     * @param enabledBase64 是否需要编码
     * @return
     */
    public static String base64EncodeStrWithCheck(String string, String noneContent, boolean enabledBase64) {
        if (!string.isEmpty() && !noneContent.equals(string) && enabledBase64){
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
}
