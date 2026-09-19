package org.bouncycastle.pqc.crypto.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal recursive-descent JSON reader for the test vector files, which no other dependency here
 * provides. Objects come back as Map, arrays as List, strings as String, numbers as Integer or
 * Double, and the three literals as Boolean or null. Not a general purpose parser: it is here to
 * read data files of a known shape, so it favours rejecting anything it does not understand over
 * accepting the wider grammar.
 */
class JsonParser
{
    static Map parseObject(InputStream in)
        throws IOException
    {
        Reader reader = new InputStreamReader(in, "UTF-8");
        StringBuffer buf = new StringBuffer();
        char[] block = new char[8192];
        int len;

        while ((len = reader.read(block)) >= 0)
        {
            buf.append(block, 0, len);
        }

        JsonParser parser = new JsonParser(buf.toString());
        Object value = parser.readValue();

        parser.skipWhitespace();
        if (parser.pos != parser.json.length())
        {
            throw new IOException("trailing content after JSON value at offset " + parser.pos);
        }
        if (!(value instanceof Map))
        {
            throw new IOException("expected a JSON object at the top level");
        }

        return (Map)value;
    }

    private final String json;
    private int pos;

    private JsonParser(String json)
    {
        this.json = json;
    }

    private Object readValue()
        throws IOException
    {
        skipWhitespace();

        char c = peek();
        switch (c)
        {
        case '{':
            return readObject();
        case '[':
            return readArray();
        case '"':
            return readString();
        case 't':
            expect("true");
            return Boolean.TRUE;
        case 'f':
            expect("false");
            return Boolean.FALSE;
        case 'n':
            expect("null");
            return null;
        default:
            return readNumber();
        }
    }

    private Map readObject()
        throws IOException
    {
        Map map = new LinkedHashMap();

        pos++;
        skipWhitespace();

        if (peek() == '}')
        {
            pos++;
            return map;
        }

        for (; ; )
        {
            skipWhitespace();

            String name = readString();

            skipWhitespace();
            if (next() != ':')
            {
                throw parseError("expected ':' after a member name");
            }

            map.put(name, readValue());

            skipWhitespace();
            char c = next();
            if (c == '}')
            {
                return map;
            }
            if (c != ',')
            {
                throw parseError("expected ',' or '}' in an object");
            }
        }
    }

    private List readArray()
        throws IOException
    {
        List list = new ArrayList();

        pos++;
        skipWhitespace();

        if (peek() == ']')
        {
            pos++;
            return list;
        }

        for (; ; )
        {
            list.add(readValue());

            skipWhitespace();
            char c = next();
            if (c == ']')
            {
                return list;
            }
            if (c != ',')
            {
                throw parseError("expected ',' or ']' in an array");
            }
        }
    }

    private String readString()
        throws IOException
    {
        if (next() != '"')
        {
            throw parseError("expected a string");
        }

        StringBuffer buf = new StringBuffer();

        for (; ; )
        {
            char c = next();

            if (c == '"')
            {
                return buf.toString();
            }

            if (c != '\\')
            {
                if (c < ' ')
                {
                    throw parseError("unescaped control character in a string");
                }
                buf.append(c);
                continue;
            }

            char esc = next();
            switch (esc)
            {
            case '"':
            case '\\':
            case '/':
                buf.append(esc);
                break;
            case 'b':
                buf.append('\b');
                break;
            case 'f':
                buf.append('\f');
                break;
            case 'n':
                buf.append('\n');
                break;
            case 'r':
                buf.append('\r');
                break;
            case 't':
                buf.append('\t');
                break;
            case 'u':
                if (pos + 4 > json.length())
                {
                    throw parseError("truncated \\u escape");
                }
                buf.append((char)Integer.parseInt(json.substring(pos, pos + 4), 16));
                pos += 4;
                break;
            default:
                throw parseError("unrecognised escape '\\" + esc + "'");
            }
        }
    }

    private Object readNumber()
        throws IOException
    {
        int start = pos;
        boolean isInteger = true;

        if (peek() == '-')
        {
            pos++;
        }

        while (pos != json.length())
        {
            char c = json.charAt(pos);
            if (c >= '0' && c <= '9')
            {
                pos++;
            }
            else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-')
            {
                isInteger = false;
                pos++;
            }
            else
            {
                break;
            }
        }

        if (pos == start)
        {
            throw parseError("expected a value");
        }

        String number = json.substring(start, pos);
        try
        {
            // the vector files only carry test case numbers, so an int is enough for those; keep a
            // double for anything else rather than failing on a file that grows a real number.
            return isInteger ? (Object)Integer.valueOf(number) : (Object)Double.valueOf(number);
        }
        catch (NumberFormatException e)
        {
            throw parseError("malformed number '" + number + "'");
        }
    }

    private void expect(String literal)
        throws IOException
    {
        if (!json.startsWith(literal, pos))
        {
            throw parseError("expected '" + literal + "'");
        }
        pos += literal.length();
    }

    private void skipWhitespace()
    {
        while (pos != json.length())
        {
            char c = json.charAt(pos);
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
            {
                return;
            }
            pos++;
        }
    }

    private char peek()
        throws IOException
    {
        if (pos == json.length())
        {
            throw parseError("unexpected end of input");
        }
        return json.charAt(pos);
    }

    private char next()
        throws IOException
    {
        char c = peek();
        pos++;
        return c;
    }

    private IOException parseError(String message)
    {
        return new IOException(message + " at offset " + pos);
    }
}
