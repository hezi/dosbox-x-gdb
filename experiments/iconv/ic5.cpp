
#include "iconvpp.hpp"

using namespace std;

// borrowed from DOSLIB
#define THIS_IS_JAPANESE "\x82\xb1\x82\xea\x82\xcd\x93\xfa\x96\x7b\x8c\xea\x82\xc5\x82\xb7"/* UTF-8 to Shift-JIS of "これは日本語です" */

typedef uint16_t test_char_t;
typedef std::basic_string<test_char_t> test_string;

int main() {
    _Iconv<char,test_char_t> *x = _Iconv<char,test_char_t>::create(/*FROM*/"SHIFT-JIS");
    if (x == NULL) {
        cerr << "Failed to create context" << endl;
        return 1;
    }

    _Iconv<test_char_t,char> *fx = _Iconv<test_char_t,char>::create("UTF-8");
    if (fx == NULL) {
        cerr << "Failed to create context" << endl;
        return 1;
    }

    {
        test_char_t tmp[512];
        const char *src = THIS_IS_JAPANESE;

        x->set_src(src);
        x->set_dest(tmp,sizeof(tmp)/sizeof(tmp[0]));

        int err = x->string_convert();

        if (err < 0) {
            cerr << "Conversion failed, " << Iconv::errstring(err) << endl;
            return 1;
        }

        cout << "Test 1: " << src << endl;
        cout << "   Res: " << fx->string_convert(tmp) << endl;
        cout << "  Read: " << x->get_src_last_read() << endl;
        cout << " Wrote: " << x->get_dest_last_written() << endl;

        x->finish();
    }

    {
        test_string dst;
        const char *src = THIS_IS_JAPANESE;

        x->set_src(src);

        int err = x->string_convert_dest(dst);

        if (err < 0) {
            cerr << "Conversion failed, " << Iconv::errstring(err) << endl;
            return 1;
        }

        cout << "Test 1: " << src << endl;
        cout << "   Res: " << fx->string_convert(dst) << endl;
        cout << "  Read: " << x->get_src_last_read() << endl;
        cout << " Wrote: " << x->get_dest_last_written() << endl;
    }

    {
        test_char_t tmp[512];
        const char *src = THIS_IS_JAPANESE;

        x->set_dest(tmp,sizeof(tmp)/sizeof(tmp[0]));

        int err = x->string_convert_src(src);

        if (err < 0) {
            cerr << "Conversion failed, " << Iconv::errstring(err) << endl;
            return 1;
        }

        cout << "Test 1: " << src << endl;
        cout << "   Res: " << fx->string_convert(tmp) << endl;
        cout << "  Read: " << x->get_src_last_read() << endl;
        cout << " Wrote: " << x->get_dest_last_written() << endl;
    }

    {
        test_char_t tmp[512];
        const std::string src = THIS_IS_JAPANESE;

        x->set_dest(tmp,sizeof(tmp)/sizeof(tmp[0]));

        int err = x->string_convert_src(src);

        if (err < 0) {
            cerr << "Conversion failed, " << Iconv::errstring(err) << endl;
            return 1;
        }

        cout << "Test 1: " << src << endl;
        cout << "   Res: " << fx->string_convert(tmp) << endl;
        cout << "  Read: " << x->get_src_last_read() << endl;
        cout << " Wrote: " << x->get_dest_last_written() << endl;
    }

    {
        test_string dst;
        const std::string src = THIS_IS_JAPANESE;

        int err = x->string_convert(dst,src);

        if (err < 0) {
            cerr << "Conversion failed, " << Iconv::errstring(err) << endl;
            return 1;
        }

        cout << "Test 1: " << src << endl;
        cout << "   Res: " << fx->string_convert(dst) << endl;
        cout << "  Read: " << x->get_src_last_read() << endl;
        cout << " Wrote: " << x->get_dest_last_written() << endl;
    }

    {
        const std::string src = THIS_IS_JAPANESE;
        test_string dst = x->string_convert(src);

        cout << "Test 1: " << src << endl;
        cout << "   Res: " << fx->string_convert(dst) << endl;
        cout << "  Read: " << x->get_src_last_read() << endl;
        cout << " Wrote: " << x->get_dest_last_written() << endl;
    }

    delete fx;
    delete x;
    return 0;
}

