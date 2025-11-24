#include <u.h>
#include <libc.h>
#include <bio.h>
#include <ctype.h>
#include "xml.h"

static char *escmap[] =
{
	"\x06\"&quot;",
	"\x06\'&apos;",
	"\x04<&lt;",
	"\x04>&gt;",
	"\x05&&amp;",
};

enum
{
	Xmlvalue = 2,
};

static char *
unxml(char *orig)
{
	char *s, *o, *e;
	int i, rsz;
	Rune r;

	for(s = orig, o = orig; *s != 0;){
next:
		if(*s == '\r'){
			*o++ = '\n';
			s += s[1] == '\n' ? 2 : 1;
			continue;
		}

		rsz = chartorune(&r, s);

		if(r == '&'){
			if(s[1] == '#' && (e = strchr(s+2, ';')) != nil && e != s+2){
				s += 2;
				if(*s == 'x'){
					*s = '0';
					o += dec16((uchar*)o, e-o, s, e-s);
				}else if(isdigit(*s)){
					*o++ = atoi(s);
				}
				s = e+1;
				continue;
			}else{
				for(i = 0; i < nelem(escmap); i++){
					if(strncmp(s, &escmap[i][2], escmap[i][0]) == 0){
						*o++ = escmap[i][1];
						s += escmap[i][0];
						goto next;
					}
				}
			}
		}

		memmove(o, s, rsz);
		if(*s == 0)
			break;
		s += rsz;
		o += rsz;
	}

	*o = 0;
	return orig;
}

static Xattr *
xmlattr(char *s, int *err)
{
	Xattr *a, *attrs;
	char *p;

	attrs = nil;
	*err = 0;

	for(; *s;){
		a = mallocz(sizeof(*a), 1);
		a->n = s;
		for(; *s && *s != '='; s++);
		if(*s != '='){
			werrstr("xml sucks (%d)", *s);
			goto error;
		}
		*s++ = 0;
		if(*s != '\'' && *s != '\"'){
			werrstr("xml is complicated (%d)", *s);
			goto error;
		}
		a->v = s+1;
		s = utfrune(a->v, *s);
		if(s == nil){
			werrstr("xml is broken");
			goto error;
		}
		*s++ = 0;
		a->next = attrs;
		a->n = unxml(a->n);
		a->v = unxml(a->v);
		attrs = a;
		if(*s == ' ')
			s++;
		if((p = strchr(a->n, ':')) != nil && strncmp(p, ":zdef", 5) == 0)
			*p = 0;
	}

	return attrs;
error:
	*err = 1;
	free(a);
	for(; attrs != nil; attrs = a){
		a = attrs->next;
		free(attrs);
	}
	return nil;
}

static Xelem *
xmlread_(Biobufhdr *h, Xelem *par, int flags)
{
	char *s, *t;
	Xelem *x, *ch;
	int r, closed, len, err;

	x = nil;

	for(;;){
		r = Bgetrune(h);
		if(r < 0){
			werrstr("xmlread: %r");
			goto error;
		}
		if(r == '<')
			break;
		if(isspacerune(r))
			continue;
		if(flags & Xmlvalue && par != nil){
			Bungetrune(h);
			if((s = Brdstr(h, '<', 1)) == nil){
				werrstr("xmlread: %r");
				goto error;
			}
			par->v = unxml(s);
			if((s = Brdstr(h, '>', 1)) == nil){
				free(par->v);
				par->v = nil;
				werrstr("xmlread: %r");
			}
			free(s);
			return nil;
		}
		werrstr("xmlread: unexpected rune (%C)", r);
		goto error;
	}

	s = Brdstr(h, '>', 1);
	if(s == nil){
		werrstr("xmlread: %r");
		goto error;
	}
	if(s[0] == '/'){
		free(s);
		return nil;
	}
	if(s[0] == '?'){
		free(s);
		return xmlread_(h, par, flags);
	}

	x = mallocz(sizeof(*x), 1);
	x->priv = s;
	x->n = s;

	if(strncmp(x->n, "zdef", 4) == 0){
		if((x->n = strchr(x->n, ':')) == nil){
			werrstr("xmlread: zdef without ':'");
			goto error;
		}
		x->n += 1;
	}

	len = strlen(s);
	if(s[len-1] == '/' || s[len-1] == '?'){
		closed = 1;
		s[len-1] = 0;
	}else
		closed = flags & Xmlstartonly;

	for(; *s && *s != ' '; s++);
	if(*s){
		*s++ = 0;
		x->a = xmlattr(s, &err);
		if(err != 0)
			goto error;
	}

	if(strcmp(x->n, "html") == 0){
		for(len = 0;; len += r){
			s = Brdstr(h, '>', 0);
			if(s == nil){
				werrstr("xmlread: %r");
				goto error;
			}

			r = strlen(s);
			x->v = realloc(x->v, len + r + 1);
			if(x->v == nil){
				werrstr("xmlread: %r");
				goto error;
			}
			strcpy(x->v+len, s);
			free(s);
			t = strstr(x->v+len, "</html>");
			if(t != nil){
				*t = 0;
				return x;
			}
		}
	}

	if(!closed){
		for(;;){
			flags = Xmlvalue;
			ch = xmlread_(h, x, flags);
			if(ch == nil)
				break;
			ch->next = x->ch;
			x->ch = ch;
		}
	}

	return x;

error:
	xmlfree(x);
	return nil;
}

Xelem *
xmlread(Biobufhdr *b, int flags)
{
	return xmlread_(b, nil, flags & Xmlstartonly);
}

void
xmlfree(Xelem *x)
{
	Xattr *a, *ta;
	Xelem *n, *n2;

	if(x == nil)
		return;

	xmlfree(x->ch);
	free(x->v);
	x->ch = nil;
	x->v = nil;
	free(x->priv);
	for(a = x->a; a != nil; a = ta){
		ta = a->next;
		free(a);
	}

	for(n = x->next; n != nil; n = n2){
		n2 = n->next;
		n->next = nil;
		xmlfree(n);
	}

	free(x);
}

Xelem *
xmlget(Xelem *x, char *path, ...)
{
	char **s;

	for(s = &path; *s != nil; s++){
		for(x = x->ch; x != nil && strcmp(x->n, *s) != 0; x = x->next);
		if(x == nil)
			return nil;
	}

	return x;
}

Xattr *
xmlgetattr(Xattr *a, char *name)
{
	for(; a != nil; a = a->next)
		if(strcmp(a->n, name) == 0)
			return a;
	return nil;
}

static void
xmlprint_(Xelem *x, int fd, int off)
{
	Xattr *a;

	for(; x != nil; x = x->next){
		fprint(fd, "%*c%q", off, ' ', x->n);
		if(x->v != nil)
			fprint(fd, "=%#q", x->v);
		for(a = x->a; a != nil; a = a->next)
			fprint(fd, " %q=%#q", a->n, a->v);
		fprint(fd, "\n");
		off += 4;
		xmlprint_(x->ch, fd, off);
		off -= 4;
	}
}

void
xmlprint(Xelem *x, int fd)
{
	xmlprint_(x, fd, 0);
}
