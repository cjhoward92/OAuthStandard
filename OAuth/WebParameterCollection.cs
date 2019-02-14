using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;

namespace OAuth
{
    public class WebParameterCollection : IList<WebParameter>, ICollection<WebParameter>, IEnumerable<WebParameter>, IEnumerable
    {
        private IList<WebParameter> _parameters;

        public virtual WebParameter this[string name]
        {
            get
            {
                IEnumerable<WebParameter> source = this.Where<WebParameter>((Func<WebParameter, bool>)(p => p.Name.Equals(name)));
                if (source.Count<WebParameter>() == 0)
                    return (WebParameter)null;
                if (source.Count<WebParameter>() == 1)
                    return source.Single<WebParameter>();
                string str = string.Join(",", source.Select<WebParameter, string>((Func<WebParameter, string>)(p => p.Value)).ToArray<string>());
                return new WebParameter(name, str);
            }
        }

        public virtual IEnumerable<string> Names
        {
            get
            {
                return this._parameters.Select<WebParameter, string>((Func<WebParameter, string>)(p => p.Name));
            }
        }

        public virtual IEnumerable<string> Values
        {
            get
            {
                return this._parameters.Select<WebParameter, string>((Func<WebParameter, string>)(p => p.Value));
            }
        }

        public WebParameterCollection(IEnumerable<WebParameter> parameters)
        {
            this._parameters = (IList<WebParameter>)new List<WebParameter>(parameters);
        }

        public WebParameterCollection(NameValueCollection collection)
          : this()
        {
            this.AddCollection(collection);
        }

        public virtual void AddRange(NameValueCollection collection)
        {
            this.AddCollection(collection);
        }

        private void AddCollection(NameValueCollection collection)
        {
            foreach (WebParameter webParameter in ((IEnumerable<string>)collection.AllKeys).Select<string, WebParameter>((Func<string, WebParameter>)(key => new WebParameter(key, collection[key]))))
                this._parameters.Add(webParameter);
        }

        public WebParameterCollection(IDictionary<string, string> collection)
          : this()
        {
            this.AddCollection(collection);
        }

        public void AddCollection(IDictionary<string, string> collection)
        {
            foreach (WebParameter webParameter in collection.Keys.Select<string, WebParameter>((Func<string, WebParameter>)(key => new WebParameter(key, collection[key]))))
                this._parameters.Add(webParameter);
        }

        public WebParameterCollection()
        {
            this._parameters = (IList<WebParameter>)new List<WebParameter>(0);
        }

        public WebParameterCollection(int capacity)
        {
            this._parameters = (IList<WebParameter>)new List<WebParameter>(capacity);
        }

        private void AddCollection(IEnumerable<WebParameter> collection)
        {
            foreach (WebParameter webParameter in collection.Select<WebParameter, WebParameter>((Func<WebParameter, WebParameter>)(parameter => new WebParameter(parameter.Name, parameter.Value))))
                this._parameters.Add(webParameter);
        }

        public virtual void AddRange(WebParameterCollection collection)
        {
            this.AddCollection((IEnumerable<WebParameter>)collection);
        }

        public virtual void AddRange(IEnumerable<WebParameter> collection)
        {
            this.AddCollection(collection);
        }

        public virtual void Sort(Comparison<WebParameter> comparison)
        {
            List<WebParameter> webParameterList = new List<WebParameter>((IEnumerable<WebParameter>)this._parameters);
            webParameterList.Sort(comparison);
            this._parameters = (IList<WebParameter>)webParameterList;
        }

        public virtual bool RemoveAll(IEnumerable<WebParameter> parameters)
        {
            WebParameter[] array = parameters.ToArray<WebParameter>();
            if (((IEnumerable<WebParameter>)array).Aggregate<WebParameter, bool>(true, (Func<bool, WebParameter, bool>)((current, parameter) => current & this._parameters.Remove(parameter))))
                return array.Length > 0;
            return false;
        }

        public virtual void Add(string name, string value)
        {
            this._parameters.Add(new WebParameter(name, value));
        }

        public virtual IEnumerator<WebParameter> GetEnumerator()
        {
            return this._parameters.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return (IEnumerator)this.GetEnumerator();
        }

        public virtual void Add(WebParameter parameter)
        {
            this._parameters.Add(parameter);
        }

        public virtual void Clear()
        {
            this._parameters.Clear();
        }

        public virtual bool Contains(WebParameter parameter)
        {
            return this._parameters.Contains(parameter);
        }

        public virtual void CopyTo(WebParameter[] parameters, int arrayIndex)
        {
            this._parameters.CopyTo(parameters, arrayIndex);
        }

        public virtual bool Remove(WebParameter parameter)
        {
            return this._parameters.Remove(parameter);
        }

        public virtual int Count
        {
            get
            {
                return this._parameters.Count;
            }
        }

        public virtual bool IsReadOnly
        {
            get
            {
                return this._parameters.IsReadOnly;
            }
        }

        public virtual int IndexOf(WebParameter parameter)
        {
            return this._parameters.IndexOf(parameter);
        }

        public virtual void Insert(int index, WebParameter parameter)
        {
            this._parameters.Insert(index, parameter);
        }

        public virtual void RemoveAt(int index)
        {
            this._parameters.RemoveAt(index);
        }

        public virtual WebParameter this[int index]
        {
            get
            {
                return this._parameters[index];
            }
            set
            {
                this._parameters[index] = value;
            }
        }
    }
}
