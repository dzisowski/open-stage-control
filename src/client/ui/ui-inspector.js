var UiWidget = require('./ui-widget'),
    UiInspectorField = require('./ui-inspector-field'),
    UiColorPicker = require('./ui-colorpicker'),
    UiModal = require('./ui-modal'),
    morph = require('nanomorph'),
    {defaults} = require('../widgets/'),
    html = require('nanohtml'),
    raw = require('nanohtml/raw'),
    fastdom = require('fastdom'),
    getCodeEditor = require('./ui-code-editor'),
    codeEditorModKey = (navigator.platform || '').match('Mac') ? 'metaKey' : 'ctrlKey'

class UiInspector extends UiWidget {

    constructor(options) {

        super(options)

        this.mounted = false

        this.expandedCategories = ['widget']

        this.widget = null

        this.container.addEventListener('fast-click', (e)=>{

            if (e.target.classList.contains('category-header')) {
                var name = e.target.getAttribute('data-name'),
                    expandedIndex = this.expandedCategories.indexOf(name)
                e.target.parentNode.classList.toggle('expanded', expandedIndex < 0)
                if (expandedIndex > -1) {
                    this.expandedCategories.splice(expandedIndex, 1)
                } else {
                    this.expandedCategories.push(name)
                }

            }

        })
        this.parentContainer = DOM.get('osc-panel-container.right')[0]

        this.colorPicker = new UiColorPicker()
        this.colorPicker.on('change', (event)=>{
            var textarea = DOM.get(this.container, `textarea[name="${this.colorPicker.name}"]`)
            if (textarea) {
                textarea[0].value = this.colorPicker.value
                DOM.dispatchEvent(textarea[0], 'change', event)
            }
        })

        this.container.addEventListener('click', (e)=>{

            var node = e.target

            if (node.tagName === 'OSC-INSPECTOR-CHECKBOX') {

                let name = node.getAttribute('name'),
                    textarea = DOM.get(this.container, `textarea[name="${name}"]`)

                if (textarea) {
                    fastdom.mutate(()=>{
                        textarea[0].value = !node.classList.contains('on')
                        DOM.dispatchEvent(textarea[0], 'change')
                    })
                }

            } else if (node.tagName === 'OSC-INSPECTOR-COLOR') {

                let name = node.getAttribute('name')

                if (this.colorPicker.name === name) {
                    this.colorPicker.close()
                } else {
                    this.colorPicker.setParent(node.parentNode)
                    this.colorPicker.setName(name)
                    this.colorPicker.setValue(node.getAttribute('value'))
                    this.colorPicker.open()
                }

            } else if (node.tagName === 'LABEL') {

                this.help(node.textContent)

            }

        })


        this.container.addEventListener('change', this.onChange.bind(this))
        this.container.addEventListener('keydown', this.onKeydown.bind(this))
        this.container.addEventListener('input', this.onInput.bind(this))

        this.lock = false
        this.clearTimeout = null

        this.helpModalOpened = false

    }

    clear() {

        this.clearTimeout = setTimeout(()=>{
            this.widget = null
            this.container.innerHTML = ''
            this.mounted = false
            this.clearTimeout = null
            this.colorPicker.close()
            this.parentContainer.classList.remove('editor-breakout')
        })

    }

    inspect(widgets) {

        if (this.clearTimeout) {
            clearTimeout(this.clearTimeout)
            this.clearTimeout = null
        }

        var content = html`<div></div>`

        var widget = widgets[0],
            props = defaults[widget.props.type],
            tabIndex = 1000,
            codeEditorFields = []

        this.widget = widget

        for (let categoryName in props) {

            if (categoryName === 'children') continue

            let category = html`<osc-inspector-category class="${this.expandedCategories.indexOf(categoryName) > -1 ? 'expanded' : ''}"></osc-inspector-category>`,
                categoryLabel = categoryName === 'class_specific' ? widget.props.type : categoryName

            if (widgets.length > 1 && categoryName === 'class_specific') categoryLabel = 'shared properties'

            category.appendChild(html`
                <div class="category-header" data-name="${categoryName}">${categoryLabel}${categoryName === 'widget' && widgets.length > 1 ? `s (${widgets.length})` : ''}</div>
            `)

            let notEmpty
            let field

            for (let propName in props[categoryName]) {

                // skip if property is not shared between selected widgets
                if (widgets.some((w)=>{
                    let shared = false
                    for (let c in defaults[widget.props.type]) {
                        if (defaults[w.props.type][c] && defaults[w.props.type][c].hasOwnProperty(propName)) {
                            shared = true
                            break
                        }
                    }
                    return !shared
                })) continue

                if (propName.includes('_separator')) {
                    if (field) field.classList.add('last-child')
                    field = html`<div class="separator">${props[categoryName][propName]}</div>`
                } else {
                    var def = defaults[widget.props.type][categoryName][propName]
                    if (field && def.editor) field.classList.add('last-child')
                    var first = !field || field.classList.contains('separator')
                    field = new UiInspectorField({
                        parent: this,
                        widget: widget,
                        name: propName,
                        value: widget.props[propName],
                        default: def,
                        tabIndex: tabIndex++
                    }).container
                    if (first) field.classList.add('first-child')

                    if (def.editor) {
                        codeEditorFields.push([propName, def.editor, def.syntaxChecker, widget])
                        field.classList.add('has-editor')
                    }
                }

                if (field)  {
                    category.appendChild(field)
                    notEmpty = true
                }

            }

            if (notEmpty) {
                content.appendChild(category)
            }

        }

        this.lock = true

        if (this.mounted) {
            morph(this.container.firstChild, content)
        } else {
            this.container.appendChild(content)
        }

        if (codeEditorFields.length) {
            let fields = DOM.get(this.container, '.has-editor')
            for (var i in codeEditorFields) {
                let [propName, language, syntax, widget] = codeEditorFields[i]
                let codeEditor = getCodeEditor(this, propName, language, syntax)
                codeEditor.bind(widget, fields[i])
            }
        }

        this.mounted = true
        this.lock = false

        if (this.colorPicker.opened) {

            var picker = DOM.get(this.container, `osc-inspector-color[name="${this.colorPicker.name}"]`)
            if (picker && picker[0]) {
                this.colorPicker.setValue(picker[0].getAttribute('value'))
                this.colorPicker.open()
            } else {
                this.colorPicker.close()
            }

        }


    }

    onChange(event) {

        if (this.lock) return

        this.lock = true

        var input = this.focusedInput || event.target

        this.focusedInput = null

        input.blur()

        if (document.activeElement === input._ace_input) input._ace_input.blur()

        var value = input.value,
            str = value.replace(/[‟“”]/g, '"').replace(/[‘’]/g, '\''), // convert invalid quote characters
            v

        try {
            v = JSON.parseFlex(str)
        } catch(err) {
            v = str
        }

        this.trigger('update', {
            propName: input.name,
            value: v,
            preventHistory: event && event.detail && event.detail.preventHistory
        })

        // this may not be reached if an error is thrown
        // but the lock will undone at the next inspect() call
        this.lock = false
    }

    onKeydown(event) {

        if (event.target.tagName === 'TEXTAREA') {

            if (event.keyCode === 13 &&
                ((!event.shiftKey && !event.target._ace) ||
                (event[codeEditorModKey] && event.target._ace))
            ) {

                event.preventDefault()
                DOM.dispatchEvent(event.target, 'change')

            } else if (event.keyCode === 27) {

                event.preventDefault()
                event.target.value = event.target.textContent
                event.target.blur()

            }

        }

    }

    onInput(event) {

        if (event.target._ace) return

        this.focusedInput = event.target

        // text autoheight
        this.focusedInput.setAttribute('rows',0)
        this.focusedInput.setAttribute('rows', this.focusedInput.value.split('\n').length)

    }

    help(name) {

        var _defaults = defaults[this.widget.getProp('type')],
            category = Object.keys(_defaults).find(x=>_defaults[x].hasOwnProperty(name)),
            defaultValue = _defaults[category][name],
            dynamic =  this.widget.isDynamicProp(name),
            htmlHelp = Array.isArray(defaultValue.help) ? defaultValue.help.join('<br/><br/>').replace(/<br\/>-/g, '-') : defaultValue.help

        htmlHelp = htmlHelp ? html`<p class="help">${raw(htmlHelp.replace(/`([^`]*)`/g, '<code>$1</code>'))}</p>` : ''

        DOM.each(htmlHelp, 'a', (el)=>{
            el.target = '_blank'
        })

        var computedValue = this.widget.getProp(name)

        if (typeof computedValue === 'string') {
            try {
                computedValue = JSON.stringify(JSON.parse(computedValue), null, ' ')
            } catch(e) {}
        } else {
            computedValue = JSON.stringify(computedValue, null, ' ')
        }

        var modal = new UiModal({closable: true, title: html`<span class="editor-help-title">${name}</span>`, html: true, content: html`
            <div class="inspector-help">

                <div class="header">
                    <p>Type: <code>${defaultValue.type}</code></p>
                    <p>Default: <code>${JSON.stringify(defaultValue.value)}</code></p>
                    ${
                        defaultValue.choices ? html`
                            <p>Choices: ${raw(defaultValue.choices.map(x=>'<code>' + x + '</code>').join(', '))}</p>
                        ` :''
                    }
                    <p>Dynamic: <code>${dynamic ? 'true' : 'false'}</code></p>
                </div>
                <div class="description">
                    ${htmlHelp}
                </div>
                <div class="computed">
                    <p>Computed value: <code class="pre">${computedValue || 'empty'}</code></p>
                </div>
            </div>
        `})


        this.helpModalOpened = true
        modal.on('close', ()=>{
            this.helpModalOpened = false
        })

    }

}

module.exports = UiInspector
