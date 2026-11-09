// Copyright Foxlin Industries. Strict JSON for the unreleased RC1 integration.
package cloud.foxlin.aegir.security;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

// Shared nonexecuting JSON parser for retained and RC1 client contracts.
final class IntegrationJson {
    private final String text;
    private int offset;
    private IntegrationJson(String text) { this.text=text; }
    static Object parse(String text) {
        if(text==null||text.length()>16777216)throw invalid();IntegrationJson parser=new IntegrationJson(text);
        Object value=parser.value(0);parser.space();
        if(parser.offset!=text.length())throw invalid();return value;
    }
    @SuppressWarnings("unchecked") static Map<String,Object> object(Object value) {
        if(!(value instanceof Map))throw invalid();return (Map<String,Object>)value;
    }
    @SuppressWarnings("unchecked") static List<Object> array(Object value) {
        if(!(value instanceof List))throw invalid();return (List<Object>)value;
    }
    static void required(Map<String,Object> map,String...names) {
        for(String name:names)if(!map.containsKey(name))throw invalid();
    }
    static String string(Object value,int maximum) {
        if(!(value instanceof String))throw invalid();String text=(String)value;
        if(text.trim().isEmpty()||text.length()>maximum||text.indexOf('\r')>=0||text.indexOf('\n')>=0||text.indexOf(0)>=0)throw invalid();return text;
    }
    static long integer(Object value,long minimum) {
        if(!(value instanceof Long)||((Long)value)<minimum)throw invalid();return (Long)value;
    }
    static boolean bool(Object value) { if(!(value instanceof Boolean))throw invalid();return (Boolean)value; }
    static IllegalArgumentException invalid(){return new IllegalArgumentException("Invalid or unsupported integration JSON.");}
    private void space(){while(offset<text.length()&&" \r\n\t".indexOf(text.charAt(offset))>=0)offset++;}
    private char next(){if(offset>=text.length())throw invalid();return text.charAt(offset++);}
    private void take(char expected){space();if(next()!=expected)throw invalid();}
    private Object value(int depth){
        if(depth>32)throw invalid();space();if(offset>=text.length())throw invalid();char c=text.charAt(offset);
        if(c=='{'){
            offset++;Map<String,Object> map=new LinkedHashMap<>();java.util.Set<String>names=new java.util.HashSet<>();space();if(offset<text.length()&&text.charAt(offset)=='}'){offset++;return map;}
            while(true){space();if(offset>=text.length()||text.charAt(offset)!='"')throw invalid();String name=quoted();take(':');if(!names.add(name.toLowerCase(java.util.Locale.ROOT)))throw invalid();map.put(name,value(depth+1));if(map.size()>100000)throw invalid();space();char separator=next();if(separator=='}')return map;if(separator!=',')throw invalid();}
        }
        if(c=='['){
            offset++;List<Object> list=new ArrayList<>();space();if(offset<text.length()&&text.charAt(offset)==']'){offset++;return list;}
            while(true){if(list.size()>=100000)throw invalid();list.add(value(depth+1));space();char separator=next();if(separator==']')return list;if(separator!=',')throw invalid();}
        }
        if(c=='"')return quoted();
        if(text.startsWith("true",offset)){offset+=4;return Boolean.TRUE;}
        if(text.startsWith("false",offset)){offset+=5;return Boolean.FALSE;}
        if(text.startsWith("null",offset)){offset+=4;return null;}
        int start=offset;while(offset<text.length()&&"-+0123456789.eE".indexOf(text.charAt(offset))>=0)offset++;
        String number=text.substring(start,offset);
        if(number.length()>128||!number.matches("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?"))throw invalid();
        try { if(number.indexOf('.')<0&&number.indexOf('e')<0&&number.indexOf('E')<0)return Long.valueOf(number);return new BigDecimal(number); }
        catch(NumberFormatException failure){throw invalid();}
    }
    private String quoted(){
        if(next()!='"')throw invalid();StringBuilder result=new StringBuilder();
        while(true){char c=next();if(c=='"')return unicode(result.toString());if(c<32)throw invalid();
            if(c=='\\'){char e=next();switch(e){case '"':case '\\':case '/':result.append(e);break;case 'b':result.append('\b');break;case 'f':result.append('\f');break;case 'n':result.append('\n');break;case 'r':result.append('\r');break;case 't':result.append('\t');break;case 'u':if(offset+4>text.length()||!text.substring(offset,offset+4).matches("[a-fA-F0-9]{4}"))throw invalid();try{result.append((char)Integer.parseInt(text.substring(offset,offset+4),16));}catch(NumberFormatException failure){throw invalid();}offset+=4;break;default:throw invalid();}}
            else result.append(c);
        }
    }
    private static String unicode(String value){for(int i=0;i<value.length();i++){char c=value.charAt(i);if(Character.isHighSurrogate(c)){if(++i>=value.length()||!Character.isLowSurrogate(value.charAt(i)))throw invalid();}else if(Character.isLowSurrogate(c))throw invalid();}return value;}
    static String stringify(Object value){
        if(value==null)return "null";
        if(value instanceof Boolean||value instanceof Number)return value.toString();
        if(value instanceof String){StringBuilder out=new StringBuilder("\"");for(char c:((String)value).toCharArray()){switch(c){case '"':out.append("\\\"");break;case '\\':out.append("\\\\");break;default:if(c<32)out.append(String.format("\\u%04x",(int)c));else out.append(c);}}return out.append('"').toString();}
        if(value instanceof Map){StringBuilder out=new StringBuilder("{");boolean first=true;for(Map.Entry<?,?> entry:((Map<?,?>)value).entrySet()){if(!first)out.append(',');first=false;out.append(stringify(entry.getKey().toString())).append(':').append(stringify(entry.getValue()));}return out.append('}').toString();}
        if(value instanceof List){StringBuilder out=new StringBuilder("[");boolean first=true;for(Object item:(List<?>)value){if(!first)out.append(',');first=false;out.append(stringify(item));}return out.append(']').toString();}
        throw invalid();
    }
}
