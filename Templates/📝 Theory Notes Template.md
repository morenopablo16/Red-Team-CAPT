<%* 
const _t = await tp.system.prompt("Topic name (e.g. OSINT Fundamentals)"); 
const _m = await tp.system.prompt("Module name (e.g. OSINT)"); 
await tp.file.rename(_t);
%>
# 📝 <% _t %>

**Module**: <% _m %> | **Date**: <% tp.date.now("YYYY-MM-DD") %>

---

## 🎯 Key Concepts

### Main Topic 1
- Key point
- Key point

### Main Topic 2  
- Key point
- Key point

---

## 📝 Notes

*Main content here*

---

## 🔗 References
- Course: [section]
- Additional: [resource]

---

#theory #<% _m.toLowerCase().replace(/\s+/g, '-') %>